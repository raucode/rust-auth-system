-- El registro de servicios: qué aplicaciones existen y adónde se puede volver.
--
-- ## Qué problema resuelve hoy
--
-- La lista de destinos válidos del redirect estaba **escrita a mano en un fichero
-- JavaScript**. Añadir un servicio significaba editar el frontend del login, y
-- cualquiera que sirviera esa página podía ampliarla. Una lista blanca que vive en
-- el cliente no es una lista blanca.
--
-- ## Qué problema resuelve mañana, que es el motivo real
--
-- Hoy todos los servicios comparten host, así que comparten cookie. **Eso se acaba
-- en cuanto uno viva en otro dominio**: los navegadores aíslan las cookies por
-- sitio —Firefox lo hace por defecto con Total Cookie Protection— y no hay
-- configuración que lo evite. Cruzar dominios exige redirección con código de un
-- solo uso, o sea OIDC.
--
-- Esta tabla **es** el registro de clientes que OIDC necesita. Adoptarlo el día que
-- haga falta será añadirle el intercambio de código, no inventar de cero de dónde
-- salen los clientes ni qué URLs de retorno son legítimas. Cuesta una tabla y
-- compra la puerta abierta; lo que sería deuda es montar hoy la criptografía
-- asimétrica para ningún cliente.

CREATE TABLE IF NOT EXISTS auth.services (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Nombre corto y estable. Es lo que usará un futuro `client_id` y lo que se
    -- escribe en la configuración del proxy: no debe cambiar aunque cambie la URL.
    slug        TEXT UNIQUE NOT NULL,
    nombre      TEXT NOT NULL,
    descripcion TEXT,

    -- El origen, sin barra final: `http://localhost:8000`. Se compara **entero** y
    -- nunca por prefijo de texto: `startsWith('http://localhost:8000')` deja pasar
    -- `http://localhost:8000.sitio-falso.com`, que es un dominio ajeno.
    --
    -- **No es único a propósito.** Detrás de un proxy, varios servicios comparten
    -- origen y se distinguen por la ruta; con subdominios, cada uno tiene el suyo.
    -- La tabla admite los dos modelos sin cambiar, que es lo que permite pasar de
    -- uno a otro editando datos en vez de esquema.
    origen      TEXT NOT NULL,

    -- Dónde aterriza quien vuelve del login, dentro de ese origen.
    ruta_inicio TEXT NOT NULL DEFAULT '/',

    -- Qué permiso hace falta para que este servicio aparezca en el portal. NULL =
    -- basta con tener sesión. No sustituye a la comprobación del propio servicio:
    -- esto decide qué se **enseña**, no qué se **permite**.
    permiso     TEXT,

    activo      BOOLEAN NOT NULL DEFAULT TRUE,
    creado_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- El origen tiene que ser un origen y no una URL con ruta: si aquí cupiera
    -- `http://host/algo`, la comparación de más arriba dejaría de significar lo
    -- que dice.
    CONSTRAINT origen_sin_ruta CHECK (origen ~ '^https?://[^/]+$')
);

CREATE INDEX IF NOT EXISTS services_origen_idx ON auth.services (origen) WHERE activo;

COMMENT ON TABLE auth.services IS
    'Aplicaciones que confían en este sistema de identidad. Lista blanca de destinos de redirect hoy; registro de clientes OIDC el día que haga falta.';

-- Los servicios tal como se ven **desde el navegador**, o sea a través del proxy.
-- Los puertos de Vite (5173-5176) son backends internos y no aparecen aquí: nadie
-- debería entrar por ellos, y el día que el proxy sea lo único alcanzable dejarán
-- de existir de cara afuera.
--
-- El login tampoco está: es la pantalla de este mismo sistema, y volver al login
-- desde el login no es un destino.
INSERT INTO auth.services (slug, nombre, descripcion, origen, ruta_inicio, permiso) VALUES
    ('portal', 'Portal',                   'La puerta de entrada: enseña lo que puedes abrir', 'http://localhost:8000', '/',      NULL),
    ('visor',  'Visor de infraestructura', 'Inventario y topología de la red',                 'http://localhost:8000', '/visor/', 'visor:leer'),
    ('demo',   'Área protegida',           'Demostración del redirect verificado',             'http://localhost:8000', '/demo/',  NULL)
ON CONFLICT (slug) DO UPDATE SET
    nombre      = EXCLUDED.nombre,
    descripcion = EXCLUDED.descripcion,
    origen      = EXCLUDED.origen,
    ruta_inicio = EXCLUDED.ruta_inicio,
    permiso     = EXCLUDED.permiso;
