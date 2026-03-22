-- ===============================
-- SCHEMA
-- ===============================
CREATE SCHEMA IF NOT EXISTS auth;

-- ===============================
-- ENUMS
-- ===============================
CREATE TYPE user_type_enum AS ENUM (
    'owner',
    'employer',
    'admin'
);

CREATE TYPE state_enum AS ENUM (
    'AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF',
    'ES', 'GO', 'MA', 'MT', 'MS', 'MG', 'PA',
    'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 'RS',
    'RO', 'RR', 'SC', 'SP', 'SE', 'TO'
);

-- ===============================
-- USERS
-- ===============================
CREATE TABLE auth.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,

    full_name TEXT NOT NULL,
    phone TEXT,

    state state_enum NOT NULL,

    user_type user_type_enum NOT NULL,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===============================
-- USERS OWNERS
-- ===============================
CREATE TABLE auth.owners (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,

    cpf TEXT NOT NULL UNIQUE,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    verified BOOLEAN NOT NULL DEFAULT FALSE


);
-- ===============================
-- USERS EMPLOYERS
-- ===============================
CREATE TABLE auth.employers (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    restaurant_id UUID NOT NULL,
    cpf TEXT,
    hire_date DATE,
    role_gerarqui INTEGER NOT NULL,
    salary NUMERIC(10,2),
    is_active BOOLEAN NOT NULL DEFAULT TRUE

);
-- ===============================
-- USERS ADMIN
-- ===============================
CREATE TABLE auth.admins (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,

    access_level INTEGER NOT NULL, -- ej: 1,2,3
    internal_note TEXT

);

-- ===============================
-- TRIGERS
-- ===============================
CREATE OR REPLACE FUNCTION auth.check_user_profile()
RETURNS trigger AS $$
BEGIN
    -- OWNER
    IF NEW.user_type = 'owner' THEN
        IF NOT EXISTS (
            SELECT 1 FROM auth.owners WHERE user_id = NEW.id
        ) THEN
            RAISE EXCEPTION
                'User % of type owner must have a record in owners table',
                NEW.id;
        END IF;
    END IF;

    -- EMPLOYER
    IF NEW.user_type = 'employer' THEN
        IF NOT EXISTS (
            SELECT 1 FROM auth.employers WHERE user_id = NEW.id
        ) THEN
            RAISE EXCEPTION
                'User % of type employer must have a record in employers table',
                NEW.id;
        END IF;
    END IF;

    -- ADMIN
    IF NEW.user_type = 'admin' THEN
        IF NOT EXISTS (
            SELECT 1 FROM auth.admins WHERE user_id = NEW.id
        ) THEN
            RAISE EXCEPTION
                'User % of type admin must have a record in admins table',
                NEW.id;
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ===============================
-- ROLES
-- ===============================
CREATE TABLE IF NOT EXISTS auth.roles (
    id UUID PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT
);

-- ===============================
-- PERMISSIONS
-- ===============================
CREATE TABLE IF NOT EXISTS auth.permissions (
    id UUID PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT
);

-- ===============================
-- USER ↔ ROLE
-- ===============================
CREATE TABLE IF NOT EXISTS auth.user_roles (
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id)
        REFERENCES auth.users(id)
        ON DELETE CASCADE,
    FOREIGN KEY (role_id)
        REFERENCES auth.roles(id)
        ON DELETE CASCADE
);

-- ===============================
-- ROLE ↔ PERMISSION
-- ===============================
CREATE TABLE IF NOT EXISTS auth.role_permissions (
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id)
        REFERENCES auth.roles(id)
        ON DELETE CASCADE,
    FOREIGN KEY (permission_id)
        REFERENCES auth.permissions(id)
        ON DELETE CASCADE
);

-- ===============================
-- PLANS (SUBSCRIPTIONS)
-- ===============================
CREATE TABLE IF NOT EXISTS auth.plans (
    id UUID PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    price_cents INTEGER NOT NULL,
    billing_interval TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- ===============================
-- FEATURES
-- ===============================
CREATE TABLE IF NOT EXISTS auth.features (
    id UUID PRIMARY KEY,
    key TEXT UNIQUE NOT NULL,
    description TEXT
);

-- ===============================
-- PLAN ↔ FEATURE
-- ===============================
CREATE TABLE IF NOT EXISTS auth.plan_features (
    plan_id UUID NOT NULL,
    feature_id UUID NOT NULL,
    PRIMARY KEY (plan_id, feature_id),
    FOREIGN KEY (plan_id)
        REFERENCES auth.plans(id)
        ON DELETE CASCADE,
    FOREIGN KEY (feature_id)
        REFERENCES auth.features(id)
        ON DELETE CASCADE
);

-- ===============================
-- USER ↔ PLAN
-- ===============================
CREATE TABLE IF NOT EXISTS auth.user_plans (
    user_id UUID PRIMARY KEY,
    plan_id UUID NOT NULL,
    started_at TIMESTAMP NOT NULL DEFAULT now(),
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id)
        REFERENCES auth.users(id)
        ON DELETE CASCADE,
    FOREIGN KEY (plan_id)
        REFERENCES auth.plans(id)
);

-- ===============================
-- REFRESH TOKEN
-- ===============================
CREATE TABLE IF NOT EXISTS auth.refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  user_agent TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  expires_at TIMESTAMPTZ NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Índice único para validar refresh tokens rápidamente
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash
ON auth.refresh_tokens(token_hash);

-- Índice para buscar tokens activos por usuario (revocación masiva)
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_revoked
ON auth.refresh_tokens(user_id, revoked);

-- Índice opcional para limpiar tokens expirados
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at
ON auth.refresh_tokens(expires_at);

