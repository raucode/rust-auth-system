-- La identidad deja de saber de restaurantes.
--
-- `auth.users` nació en un SaaS de gestión de restaurantes y se trajo puesto todo
-- el negocio: un `user_type` que solo sabe decir dueño, empleado o administrador,
-- y tres tablas satélite con CPF, fecha de contratación, jerarquía laboral y
-- salario. En un componente de identidad reutilizable eso no es una columna de
-- más: es vocabulario ajeno que cada consumidor nuevo tiene que rodear. El primero
-- que lo topa es Gardenia Z, donde un jugador tendría que darse de alta como
-- «owner» y rellenar un nombre completo que nadie le ha pedido.
--
-- Esto continúa lo que empezó `20260810080000_quitar_state_y_phone`: la identidad
-- guarda lo justo para saber quién eres y qué puedes hacer.
--
-- No se edita ninguna migración ya aplicada. Sobre una base nueva las viejas crean
-- esto y ésta lo retira, que es feo de leer y correcto de ejecutar; sobre una base
-- existente retira lo que sobra sin tocar `auth.users.id`, que es la única columna
-- a la que apunta alguien desde fuera.

-- Las tres satélite se van enteras. Ninguna tiene datos que la identidad
-- necesite: son la ficha laboral de otro producto.
DROP TABLE IF EXISTS auth.employers;
DROP TABLE IF EXISTS auth.owners;
DROP TABLE IF EXISTS auth.admins;

-- `user_type` no es un rol: los roles viven en `auth.user_roles` desde el RBAC del
-- 2026-08-10, y tener las dos cosas a la vez obliga a decidir cuál manda. Manda el
-- RBAC, así que ésta se va.
ALTER TABLE auth.users DROP COLUMN IF EXISTS user_type;
DROP TYPE IF EXISTS user_type_enum;

-- Un nombre para mostrar es razonable; exigirlo no. Quien se identifica con un
-- correo y una contraseña ya es alguien, y forzar el NOT NULL solo consigue que el
-- consumidor invente un relleno — que es exactamente lo que hacía el arranque del
-- administrador inicial poniendo 'Administrador' a pelo.
ALTER TABLE auth.users ALTER COLUMN full_name DROP NOT NULL;
