-- Fuera `state` y `phone` de la identidad.
--
-- Las dos son restos del SaaS de restaurantes. `state` era **NOT NULL** con los 27
-- estados de Brasil, así que cada alta tenía que inventarse uno: el administrador
-- inicial se creaba con `'GO'` porque había que poner algo, no porque signifique
-- nada. `phone` nunca se usó para nada.
--
-- El criterio: **la identidad guarda lo que hace falta para saber quién eres y
-- qué puedes hacer.** El resto son datos del negocio, y su sitio es el sistema que
-- los necesite. Un teléfono en la tabla de identidades es un dato personal que
-- alguien va a tener que borrar cuando esa persona se vaya, guardado donde nadie
-- lo va a buscar.
--
-- **Esto borra datos y no se deshace.** Se hizo copia previa con `pg_dump` antes
-- de aplicarla la primera vez.

ALTER TABLE auth.users DROP COLUMN IF EXISTS state;
ALTER TABLE auth.users DROP COLUMN IF EXISTS phone;

-- El tipo solo lo usaba esa columna: dejarlo sería dejar los 27 estados de Brasil
-- definidos en el sistema de identidad de una empresa que no los necesita.
DROP TYPE IF EXISTS public.state_enum;

-- `user_type_enum` **se queda, de momento**. Todavía es NOT NULL en la tabla y el
-- alta lo usa para decidir en qué perfil (`owners`/`employers`/`admins`) escribe.
-- Retirarlo es la separación completa de identidad y negocio, y eso depende de
-- una decisión que no está tomada: si las personas salen de un padrón propio o
-- del Active Directory.
