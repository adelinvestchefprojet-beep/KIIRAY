-- MOUV SUITE — première création sécurisée du compte administrateur par e-mail
-- À exécuter UNE FOIS dans Supabase > SQL Editor.
-- Cette migration ne supprime aucune table ni aucune donnée.
-- L'administrateur initial est strictement limité à kiiraysn@gmail.com.
-- Le compte Auth doit être créé manuellement par le propriétaire du projet et son e-mail confirmé.

begin;

create or replace function public.mouv_first_admin_exists()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.mouv_profiles p
    where p.role::text = 'qg_national'
  );
$$;

revoke all on function public.mouv_first_admin_exists() from public;
grant execute on function public.mouv_first_admin_exists() to anon, authenticated;

create or replace function public.mouv_bootstrap_first_admin(p_full_name text)
returns boolean
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_user auth.users%rowtype;
  v_name text;
  v_email text;
begin
  if auth.uid() is null then
    raise exception 'Connectez-vous avec le compte administrateur avant de continuer.';
  end if;

  -- Sérialise les tentatives concurrentes : un seul premier administrateur.
  perform pg_advisory_xact_lock(hashtext('mouv_suite_first_admin_bootstrap'));

  if exists (
    select 1 from public.mouv_profiles p
    where p.role::text = 'qg_national'
  ) then
    raise exception 'Un administrateur national existe déjà. Configuration initiale fermée.';
  end if;

  select u.*
    into v_user
  from auth.users u
  where u.id = auth.uid();

  if v_user.id is null then
    raise exception 'Compte Auth introuvable.';
  end if;

  v_email := lower(trim(coalesce(v_user.email, '')));
  if v_email <> 'kiiraysn@gmail.com' then
    raise exception 'La première configuration est réservée à kiiraysn@gmail.com.';
  end if;

  if v_user.email_confirmed_at is null then
    raise exception 'L’adresse e-mail doit être confirmée dans Supabase avant d’activer l’administrateur.';
  end if;

  if exists (select 1 from public.mouv_profiles p where p.id = v_user.id) then
    raise exception 'Un profil existe déjà pour ce compte. Vérifiez-le avant de continuer.';
  end if;

  v_name := nullif(trim(coalesce(p_full_name, v_user.raw_user_meta_data->>'full_name', '')), '');
  if v_name is null then
    raise exception 'Nom complet manquant. Recommencez avec votre nom.';
  end if;

  insert into public.mouv_profiles (id, phone, full_name, role, status)
  values (v_user.id, coalesce(v_user.phone, ''), v_name, 'qg_national', 'active');

  return true;
end;
$$;

revoke all on function public.mouv_bootstrap_first_admin(text) from public, anon;
grant execute on function public.mouv_bootstrap_first_admin(text) to authenticated;

commit;
