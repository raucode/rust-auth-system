-- La matriz, rehecha: **quién usa** y **quién administra** son cosas distintas.
--
-- La primera versión (`20260810070000`) repartía los permisos por nivel de
-- escalado, como en un helpdesk clásico: `helpdesk` mira, `support` toca, `adm`
-- todo. Raul lo corrigió el mismo día y el corte real es otro:
--
--   * **`user` opera el servicio.** Crea planos, sube infraestructura, edita el
--     inventario. Es quien hace el trabajo, y por eso tiene los permisos fuertes
--     sobre el visor.
--   * **`helpdesk` administra cuentas.** Da de alta, edita y reparte roles. No
--     necesita tocar el inventario para hacerlo.
--
-- Que el rol «más bajo» tenga más permisos que el «administrativo» solo suena
-- raro si se piensa en rangos. **No son rangos: son responsabilidades.** Un
-- servicio no tiene por qué usar los cinco roles — al visor le bastan dos
-- comportamientos, y el resto de roles caen en uno de ellos.
--
-- Idempotente. La matriz se borra y se reescribe entera: este fichero es la
-- fuente de verdad.

-- ---------------------------------------------------------------------------
-- 1. Un permiso nuevo, y el porqué de separarlo
-- ---------------------------------------------------------------------------
-- `usuarios:gestionar` y `rbac:administrar` parecen lo mismo y no lo son:
-- **administrar cuentas y repartir poder son cosas distintas.** Quien puede
-- conceder roles puede concederse el suyo, así que `helpdesk` reparte roles
-- normales pero **no puede crear administradores**: eso lo impide el código, en
-- `asignar_rol`, no esta tabla.
INSERT INTO auth.permissions (name, description) VALUES
    ('cuentas:restablecer', 'Restablecer la contrasena de otra persona')
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description;

-- ---------------------------------------------------------------------------
-- 2. La matriz
-- ---------------------------------------------------------------------------
DELETE FROM auth.role_permissions
WHERE role_id IN (SELECT id FROM auth.roles WHERE name IN ('adm','support','helpdesk','user','servicio'));

-- adm: todo lo que exista, también lo que se añada después.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM auth.roles r CROSS JOIN auth.permissions p
WHERE r.name = 'adm';

-- user: **opera el visor de punta a punta.** Es el rol que hace el trabajo.
-- No toca cuentas: para eso está helpdesk.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM auth.roles r JOIN auth.permissions p ON p.name IN (
    'visor:leer', 'visor:editar', 'visor:administrar',
    'tickets:abrir'
) WHERE r.name = 'user';

-- helpdesk: administra cuentas. Ve el inventario porque atendiendo un ticket hace
-- falta mirar, pero **no lo modifica** — quien lo modifica es quien lo opera.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM auth.roles r JOIN auth.permissions p ON p.name IN (
    'visor:leer',
    'usuarios:leer', 'usuarios:gestionar', 'cuentas:restablecer',
    'rbac:administrar',
    'tickets:abrir', 'tickets:atender'
) WHERE r.name = 'helpdesk';

-- support: lo mismo que helpdesk más el histórico de tickets. En el visor los dos
-- se comportan igual, que es de lo que se trata: el visor no distingue cinco
-- roles, distingue dos cosas.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM auth.roles r JOIN auth.permissions p ON p.name IN (
    'visor:leer',
    'usuarios:leer', 'usuarios:gestionar', 'cuentas:restablecer',
    'rbac:administrar',
    'tickets:abrir', 'tickets:atender', 'tickets:administrar'
) WHERE r.name = 'support';

-- servicio: sigue sin ninguna fila, a propósito.
