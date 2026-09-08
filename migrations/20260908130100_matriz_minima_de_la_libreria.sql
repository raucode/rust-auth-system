-- El catálogo de permisos sale de la librería.
--
-- Las migraciones del RBAC sembraron roles y permisos de dominios concretos:
-- `visor:*` del visor de infraestructura, `tickets:*` de la mesa de ayuda,
-- `inventory:*` del inventario, más una lista de servicios que apunta a
-- `localhost:8000`. Eso convierte a la librería en la dueña del vocabulario de
-- todos, y se nota en cuanto entra un consumidor de otro dominio: un jugador de
-- Gardenia Z con el rol `user` heredaría `visor:leer` e `inventory:write`.
--
-- Peor todavía, dos de esas migraciones hacen `DELETE FROM auth.role_permissions`
-- y reescriben la matriz entera de cinco roles. Mientras eso viva aquí, cada
-- despliegue de la librería pisa las concesiones del consumidor.
--
-- A partir de ahora la librería trae **las tablas**, y cada proyecto siembra sus
-- roles y sus permisos en una migración suya. Se queda solo lo que el código de
-- esta librería exige por su cuenta:
--
--   · el rol `adm`, que `rbac/handler_rbac.rs` trata aparte para que nadie pueda
--     retirar el último administrador y dejar la base sin quien conceda permisos;
--   · el permiso `rbac:administrar`, que `rbac/routes_rbac.rs` exige en su ámbito.
--
-- Administrar identidades es el dominio de esta librería, así que ese par sí es
-- suyo. Todo lo demás no.
--
-- Los servicios que quedaban en `auth.services` eran datos de un despliegue
-- concreto, no de la librería: la tabla se queda (la usa `servicios.rs` como lista
-- blanca de destinos) y las filas se van.

-- El orden importa: primero las concesiones, luego las asignaciones a personas y
-- solo al final los catálogos. Si alguna clave ajena no tuviera CASCADE, borrar al
-- revés fallaría a mitad y dejaría la matriz peor que antes.
DELETE FROM auth.role_permissions
WHERE permission_id IN (
    SELECT id FROM auth.permissions WHERE name <> 'rbac:administrar'
);

DELETE FROM auth.role_permissions
WHERE role_id IN (SELECT id FROM auth.roles WHERE name <> 'adm');

DELETE FROM auth.user_roles
WHERE role_id IN (SELECT id FROM auth.roles WHERE name <> 'adm');

DELETE FROM auth.permissions WHERE name <> 'rbac:administrar';
DELETE FROM auth.roles       WHERE name <> 'adm';

-- `adm` conserva lo único que queda en el catálogo. Cuando un consumidor añada sus
-- permisos, es él quien decide si `adm` los recibe.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM auth.roles r, auth.permissions p
WHERE r.name = 'adm' AND p.name = 'rbac:administrar'
ON CONFLICT (role_id, permission_id) DO NOTHING;

DELETE FROM auth.services;
