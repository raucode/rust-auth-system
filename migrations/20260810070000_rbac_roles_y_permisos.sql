-- RBAC: el catálogo de roles y permisos, como datos versionados.
--
-- Las cuatro tablas (roles, permissions, user_roles, role_permissions) existían
-- desde la migración inicial y estaban **vacías**, y ningún fichero de `src/` las
-- consultaba: el sistema sabía quién eras y no qué podías hacer. Esto las llena.
--
-- Va en una migración y no en un script suelto por una razón concreta: **quién
-- puede qué es una decisión auditable**. En Git tiene fecha, autor y motivo; en un
-- psql de alguien una tarde, no existe.
--
-- Es idempotente entera: se puede volver a aplicar sin duplicar nada ni pisar una
-- descripción editada a mano.

-- ---------------------------------------------------------------------------
-- 0. Que la base genere los identificadores
-- ---------------------------------------------------------------------------
-- Las tres tablas tienen `id UUID PRIMARY KEY` **sin DEFAULT**, así que hasta
-- ahora cada INSERT tenía que inventarse el UUID por su cuenta. `gen_random_uuid()`
-- es nativa desde PostgreSQL 13 — ya no hace falta la extensión pgcrypto.
ALTER TABLE auth.roles       ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE auth.permissions ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- ---------------------------------------------------------------------------
-- 1. Roles
-- ---------------------------------------------------------------------------
-- Cinco, deliberadamente pocos. Un catálogo de roles crece solo; empezar con
-- veinte garantiza que nadie sepa cuál toca. Si un caso no encaja en estos, la
-- respuesta suele ser un permiso nuevo, no un rol nuevo.
INSERT INTO auth.roles (name, description) VALUES
    ('adm',      'Administración total, incluida la gestión de identidades y permisos'),
    ('support',  'Soporte de segundo nivel: opera la infraestructura y resuelve lo que escala helpdesk'),
    ('helpdesk', 'Primer nivel: atiende tickets y consulta el inventario, sin modificarlo'),
    ('user',     'Usuario final de la organización: abre tickets y ve lo suyo'),
    ('servicio', 'Cuenta de máquina para integraciones y scripts. Nace sin ningún permiso: se le concede solo lo que ese script necesita')
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description;

-- ---------------------------------------------------------------------------
-- 2. Permisos
-- ---------------------------------------------------------------------------
-- Vocabulario `recurso:accion`. El recurso es el sistema, no la pantalla: si se
-- nombran pantallas, cada rediseño de la interfaz obliga a migrar permisos.
INSERT INTO auth.permissions (name, description) VALUES
    ('visor:leer',           'Ver el inventario y la topología de la red'),
    ('visor:editar',         'Dar de alta, modificar y conectar equipos'),
    ('visor:administrar',    'Importar y exportar el inventario, y editar los planos'),
    ('tickets:abrir',        'Crear tickets propios y seguir su estado'),
    ('tickets:atender',      'Tomar, responder y cerrar tickets de otros'),
    ('tickets:administrar',  'Reasignar, reabrir y ver el histórico completo'),
    ('usuarios:leer',        'Consultar el padrón de usuarios'),
    ('usuarios:gestionar',   'Alta, baja y modificación de usuarios'),
    ('rbac:administrar',     'Conceder y retirar roles. Es el permiso que concede permisos')
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description;

-- ---------------------------------------------------------------------------
-- 3. Qué puede cada rol
-- ---------------------------------------------------------------------------
-- Se borra y se reescribe en la misma transacción: así este fichero es **la**
-- fuente de verdad de la matriz. Si se hiciera solo con INSERT ... ON CONFLICT,
-- retirar un permiso aquí no lo retiraría en una base ya sembrada, y el fichero
-- diría una cosa mientras la base hace otra.
DELETE FROM auth.role_permissions
WHERE role_id IN (SELECT id FROM auth.roles WHERE name IN ('adm','support','helpdesk','user','servicio'));

-- adm: todo lo que exista, también lo que se añada en el futuro.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM auth.roles r CROSS JOIN auth.permissions p
WHERE r.name = 'adm';

-- support: opera la infraestructura y resuelve tickets. No toca identidades.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM auth.roles r JOIN auth.permissions p ON p.name IN (
    'visor:leer', 'visor:editar',
    'tickets:abrir', 'tickets:atender', 'tickets:administrar',
    'usuarios:leer'
) WHERE r.name = 'support';

-- helpdesk: consulta el inventario pero no lo modifica — ese es justo el corte
-- entre primer y segundo nivel, y por eso no lleva `visor:editar`.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM auth.roles r JOIN auth.permissions p ON p.name IN (
    'visor:leer',
    'tickets:abrir', 'tickets:atender'
) WHERE r.name = 'helpdesk';

-- user: abre tickets y nada más. No ve el inventario: a un usuario final la
-- topología de la red no le sirve, y sí es un mapa útil para quien no debe tenerlo.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM auth.roles r JOIN auth.permissions p ON p.name IN (
    'tickets:abrir'
) WHERE r.name = 'user';

-- servicio: a propósito sin ninguna fila. Una cuenta de máquina recibe sus
-- permisos uno a uno, del script concreto que la usa.
