-- El inventario entra en la matriz, y el registro de servicios.
--
-- ## Qué cambia
--
-- Nace el servicio `inventory` (repositorio `raucode/inventory`): la fuente única
-- del bien —equipos de TI, herramientas y licencias—, que hasta hoy vivía dentro
-- de la tabla `assets` del visor.
--
-- ## Esta migración releva a `20260810090000` como fuente de verdad de la matriz
--
-- Aquella decía, con razón, que la matriz se borra y se reescribe entera para que
-- el fichero no pueda quedar diciendo una cosa mientras la base hace otra. El
-- precio es que **solo puede haber un fichero vigente**, y a partir de ahora es
-- este: repite la matriz completa con el inventario dentro. Reescribir solo los
-- permisos nuevos dejaría la política repartida en dos sitios, que es justo lo
-- que aquella decisión evitaba.
--
-- ## Los permisos nuevos van en inglés y los viejos no
--
-- Desde el 2026-08-11 los identificadores se escriben en inglés (la regla está en
-- el vault, `00-User Agent/Idioma del código y de la interfaz`). Así que la tabla
-- queda con `visor:leer` al lado de `inventory:read`, y **eso es deliberado**:
-- renombrar los del visor tocaría una migración ya aplicada y los tokens en
-- circulación, que llevan los permisos resueltos dentro de las cabeceras. Se
-- renombrarán el día que haya otro motivo para tocarlos.

-- ---------------------------------------------------------------------------
-- 1. Los tres permisos del inventario
-- ---------------------------------------------------------------------------
-- El mismo corte de tres niveles que el visor, y por el mismo motivo: la capa que
-- los aplica corta por método HTTP, no ruta por ruta. `admin` cubre lo que toca
-- el inventario entero de golpe —importar un CSV, editar el catálogo de tipos—,
-- porque una importación mal hecha reescribe doscientos equipos y de eso no se
-- vuelve sin copia de seguridad.
INSERT INTO auth.permissions (name, description) VALUES
    ('inventory:read',  'Ver o inventário de bens'),
    ('inventory:write', 'Criar, editar e dar baixa em bens'),
    ('inventory:admin', 'Catálogo de tipos e importações em massa')
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description;

-- ---------------------------------------------------------------------------
-- 2. La matriz, entera
-- ---------------------------------------------------------------------------
DELETE FROM auth.role_permissions
WHERE role_id IN (SELECT id FROM auth.roles WHERE name IN ('adm','support','helpdesk','user','servicio'));

-- adm: todo lo que exista, también lo que se añada después.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM auth.roles r CROSS JOIN auth.permissions p
WHERE r.name = 'adm';

-- user: opera. Es quien hace el trabajo, y el inventario es trabajo suyo — quien
-- monta una cámara es quien sabe su número de serie y dónde quedó.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM auth.roles r JOIN auth.permissions p ON p.name IN (
    'visor:leer', 'visor:editar', 'visor:administrar',
    'inventory:read', 'inventory:write', 'inventory:admin',
    'tickets:abrir'
) WHERE r.name = 'user';

-- helpdesk: administra cuentas y **mira** el inventario. Atendiendo un ticket
-- hace falta saber qué equipo tiene esa persona; cambiarlo es de quien lo opera.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM auth.roles r JOIN auth.permissions p ON p.name IN (
    'visor:leer',
    'inventory:read',
    'usuarios:leer', 'usuarios:gestionar', 'cuentas:restablecer',
    'rbac:administrar',
    'tickets:abrir', 'tickets:atender'
) WHERE r.name = 'helpdesk';

-- support: lo mismo más el histórico de tickets. En el inventario los dos se
-- comportan igual, que es de lo que se trata: el servicio no distingue cinco
-- roles, distingue tres cosas.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM auth.roles r JOIN auth.permissions p ON p.name IN (
    'visor:leer',
    'inventory:read',
    'usuarios:leer', 'usuarios:gestionar', 'cuentas:restablecer',
    'rbac:administrar',
    'tickets:abrir', 'tickets:atender', 'tickets:administrar'
) WHERE r.name = 'support';

-- servicio: sigue sin ninguna fila, a propósito. Nace con cero permisos para que
-- una integración tenga que pedir explícitamente lo que necesita.

-- ---------------------------------------------------------------------------
-- 3. El servicio, en el registro
-- ---------------------------------------------------------------------------
-- Con esto aparece en el portal y su URL pasa a ser un destino legítimo del
-- redirect del login. El origen es el **de la puerta**, no el del backend: por el
-- 8082 no debería entrar nadie.
INSERT INTO auth.services (slug, nombre, descripcion, origen, ruta_inicio, permiso) VALUES
    ('inventory', 'Inventário', 'Equipamentos, ferramentas e licenças', 'http://localhost:8003', '/', 'inventory:read')
ON CONFLICT (slug) DO UPDATE SET
    nombre      = EXCLUDED.nombre,
    descripcion = EXCLUDED.descripcion,
    origen      = EXCLUDED.origen,
    ruta_inicio = EXCLUDED.ruta_inicio,
    permiso     = EXCLUDED.permiso;
