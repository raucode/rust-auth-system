-- Las suscripciones tampoco son identidad.
--
-- `auth.plans`, `auth.features`, `auth.plan_features` y `auth.user_plans` venían
-- en la primera migración, del mismo SaaS de restaurantes que trajo la ficha de
-- empleado. **Ninguna línea de `src/` las ha usado nunca**: no hay modelo, ni
-- repositorio, ni ruta que las toque. Son cuatro tablas que solo existían para que
-- cada consumidor nuevo se preguntara qué hacen ahí.
--
-- Se van con la misma regla que el resto: qué plan tiene alguien contratado no
-- responde ni a «quién eres» ni a «qué puedes hacer». Responde a «qué has pagado»,
-- que es una pregunta del producto y no de la identidad. Gardenia Z, por ejemplo,
-- modela sus canales y sus derechos en `game.entitlements`, que no se parece en
-- nada a esto — y ese es justo el argumento.
--
-- Si algún día un consumidor quiere planes, los declara en su esquema, con la
-- forma que necesite.

-- Primero las que apuntan a otras, o las claves ajenas lo impiden.
DROP TABLE IF EXISTS auth.user_plans;
DROP TABLE IF EXISTS auth.plan_features;
DROP TABLE IF EXISTS auth.plans;
DROP TABLE IF EXISTS auth.features;
