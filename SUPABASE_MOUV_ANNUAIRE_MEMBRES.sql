-- MOUV SUITE / KIIRAY — Annuaire partagé des membres
-- Migration additive : ne supprime aucune table, aucun profil ni aucune donnée existante.
-- À exécuter dans Supabase > SQL Editor après sauvegarde.
-- Les militants n'ont pas besoin d'un compte Auth individuel pour figurer dans l'annuaire.
-- Les coordinateurs et l'administrateur doivent avoir un compte Auth actif.

begin;

create table if not exists public.mouv_annuaire_members (
  id uuid primary key default gen_random_uuid(),
  full_name text not null check (char_length(trim(full_name)) >= 2),
  phone text not null,
  commune text not null check (char_length(trim(commune)) >= 2),
  member_role text not null default 'militant'
    check (member_role in ('coordinateur','militant')),
  coordinator_auth_id uuid null references auth.users(id) on delete set null,
  created_by uuid null references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists mouv_annuaire_members_phone_unique
  on public.mouv_annuaire_members (regexp_replace(phone, '[^0-9+]', '', 'g'));

create index if not exists mouv_annuaire_members_commune_idx
  on public.mouv_annuaire_members (lower(commune));

create index if not exists mouv_annuaire_members_coordinator_idx
  on public.mouv_annuaire_members (coordinator_auth_id);

alter table public.mouv_annuaire_members enable row level security;

-- Vérifie le rôle et le statut de la personne connectée.
create or replace function public.mouv_current_role()
returns text
language sql
stable
security definer
set search_path = public, auth
as $$
  select p.role::text
  from public.mouv_profiles p
  where p.id = auth.uid()
    and p.status::text = 'active'
  limit 1;
$$;

-- L'administrateur et les coordinateurs actifs peuvent lire les fiches complètes.
-- Les militants ne peuvent lire les fiches complètes via cette table.
drop policy if exists mouv_annuaire_staff_read on public.mouv_annuaire_members;
create policy mouv_annuaire_staff_read
on public.mouv_annuaire_members
for select to authenticated
using (
  public.mouv_current_role() = 'qg_national'
  or (
    public.mouv_current_role() = 'coordinateur'
    and (
      coordinator_auth_id = auth.uid()
      or lower(commune) = lower(coalesce((
        select own_member.commune
        from public.mouv_annuaire_members own_member
        where own_member.coordinator_auth_id = auth.uid()
          and own_member.member_role = 'coordinateur'
        order by own_member.created_at
        limit 1
      ), ''))
    )
  )
);

-- Écriture directe interdite : les ajouts passent par la fonction contrôlée ci-dessous.
drop policy if exists mouv_annuaire_no_direct_insert on public.mouv_annuaire_members;
create policy mouv_annuaire_no_direct_insert
on public.mouv_annuaire_members
for insert to authenticated
with check (false);

drop policy if exists mouv_annuaire_no_direct_update on public.mouv_annuaire_members;
create policy mouv_annuaire_no_direct_update
on public.mouv_annuaire_members
for update to authenticated
using (false) with check (false);

drop policy if exists mouv_annuaire_no_direct_delete on public.mouv_annuaire_members;
create policy mouv_annuaire_no_direct_delete
on public.mouv_annuaire_members
for delete to authenticated
using (false);

-- Annuaire public en lecture seule : expose uniquement nom, commune et rôle,
-- jamais les numéros de téléphone ni les identifiants de compte.
create or replace view public.mouv_public_members
with (security_barrier = true)
as
select id, full_name, commune, member_role, created_at
from public.mouv_annuaire_members;

revoke all on public.mouv_annuaire_members from anon, authenticated;
grant select on public.mouv_annuaire_members to authenticated;
grant select on public.mouv_public_members to anon, authenticated;

-- Fonction sécurisée pour ajouter un membre sans créer un compte Auth pour chaque militant.
create or replace function public.mouv_add_directory_member(
  p_full_name text,
  p_phone text,
  p_commune text,
  p_member_role text default 'militant',
  p_coordinator_auth_id uuid default null
)
returns public.mouv_annuaire_members
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_role text;
  v_commune text;
  v_coordinator uuid;
  v_result public.mouv_annuaire_members;
begin
  if auth.uid() is null then
    raise exception 'Connexion requise.';
  end if;

  select p.role::text
    into v_role
  from public.mouv_profiles p
  where p.id = auth.uid()
    and p.status::text = 'active';

  if v_role = 'coordinateur' then
    select own_member.commune
      into v_commune
    from public.mouv_annuaire_members own_member
    where own_member.coordinator_auth_id = auth.uid()
      and own_member.member_role = 'coordinateur'
    order by own_member.created_at
    limit 1;
  end if;

  if v_role is null then
    raise exception 'Profil actif introuvable.';
  end if;

  if length(trim(coalesce(p_full_name,''))) < 2
     or length(trim(coalesce(p_phone,''))) < 6
     or length(trim(coalesce(p_commune,''))) < 2 then
    raise exception 'Nom, téléphone et commune sont obligatoires.';
  end if;

  if p_member_role not in ('coordinateur','militant') then
    raise exception 'Rôle de membre invalide.';
  end if;

  if p_member_role = 'coordinateur' and v_role <> 'qg_national' then
    raise exception 'Seul l’administrateur national peut désigner un coordinateur.';
  end if;

  if v_role not in ('qg_national','coordinateur') then
    raise exception 'Droits insuffisants pour ajouter un membre.';
  end if;

  if v_role = 'coordinateur' then
    v_coordinator := auth.uid();
    -- Un coordinateur ne peut ajouter que dans sa propre commune.
    if lower(trim(p_commune)) <> lower(trim(coalesce(v_commune,''))) then
      raise exception 'Vous ne pouvez ajouter des militants que dans votre commune.';
    end if;
    if p_member_role <> 'militant' then
      raise exception 'Un coordinateur ne peut pas désigner un autre coordinateur.';
    end if;
  else
    v_coordinator := p_coordinator_auth_id;
    if v_coordinator is not null and not exists (
      select 1 from public.mouv_profiles cp
      where cp.id = v_coordinator
        and cp.role::text = 'coordinateur'
        and cp.status::text = 'active'
    ) then
      raise exception 'Le coordinateur choisi n’est pas actif ou n’existe pas.';
    end if;
  end if;

  insert into public.mouv_annuaire_members
    (full_name, phone, commune, member_role, coordinator_auth_id, created_by)
  values
    (trim(p_full_name), trim(p_phone), trim(p_commune), p_member_role, v_coordinator, auth.uid())
  returning * into v_result;

  return v_result;
end;
$$;

-- La vue n'expose aucune donnée privée. La fonction d'ajout contrôle le rôle côté serveur.
revoke all on function public.mouv_current_role() from public;
grant execute on function public.mouv_current_role() to authenticated;
revoke all on function public.mouv_add_directory_member(text,text,text,text,uuid) from public, anon;
grant execute on function public.mouv_add_directory_member(text,text,text,text,uuid) to authenticated;

commit;

-- IMPORTANT :
-- 1) Il faut créer d'abord le compte Auth de l'administrateur dans Supabase Dashboard.
-- 2) Vérifier que son profil est présent dans public.mouv_profiles, avec role='qg_national' et status='active'.
-- 3) Les coordinateurs ont aussi besoin d'un compte Auth actif et d'un profil role='coordinateur'.
-- 4) Ce script crée l'annuaire partagé côté base. L'interface web doit ensuite être reliée à
--    mouv_public_members (consultation) et mouv_add_directory_member (ajout sécurisé).
