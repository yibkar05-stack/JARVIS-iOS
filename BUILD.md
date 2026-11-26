# Compilar JARVIS Device Agent

Se requiere macOS 15, Xcode 16.4 y el SDK de iPhoneOS incluido en Xcode. El
destino es iPhone arm64 con iOS 15 o posterior. El script usa directamente
el compilador de Swift de Xcode. El IPA es un artefacto sin firma y requiere
firma antes de instalarse en un iPhone.

## Compilación local y verificación

Desde la raíz del repositorio en macOS, con Xcode 16.4 instalado en la ruta
indicada, ejecuta:

```bash
export DEVELOPER_DIR=/Applications/Xcode_16.4.app/Contents/Developer
bash scripts/build-unsigned.sh
cd dist
shasum -a 256 -c JARVIS-unsigned.ipa.sha256
unzip -l JARVIS-unsigned.ipa
```

El verificador debe mostrar `JARVIS-unsigned.ipa: OK`. El script comprueba
la arquitectura arm64, la ausencia de `LC_CODE_SIGNATURE` en el ejecutable
y la integridad del ZIP. El paquete contiene `Payload/JARVIS.app`.

## GitHub Actions

El workflow se inicia con un push a `main` o desde **Actions → Build unsigned
JARVIS IPA → Run workflow**. Usa la etiqueta estándar `macos-15` y selecciona
Xcode 16.4. Ejecuta dos compilaciones en la misma imagen y exige que sus
SHA-256 coincidan antes de publicar `JARVIS-unsigned`. Descarga y descomprime
ese artefacto, y ejecuta `shasum -a 256 -c JARVIS-unsigned.ipa.sha256` en la
carpeta que contiene ambos archivos. La suma también figura en el resumen
de la corrida. La prueba compara dos compilaciones en el mismo entorno.

## Perfil JDB-1 para el laboratorio

Configura la raíz HTTPS del gateway y guarda por separado la credencial Bearer
del dispositivo y una clave HMAC de desarrollo de 32 bytes en Base64. Ambos
valores se ingresan manualmente y se guardan en Keychain con acceso solo al
desbloquear el dispositivo. HMAC requiere un secreto compartido y el perfil usa
exclusivamente una clave de laboratorio dedicada al gateway. Una firma con
clave pública para el tramo al iPhone requiere un acuerdo de protocolo aparte.

El contrato de Fase 2 deja abiertas las rutas y el encuadre de la firma de la
respuesta. Este cliente propone las siguientes convenciones para cotejo con
MAUS y el gateway antes de la integración.

- `GET /task` devuelve 204 si la cola está vacía o 200 con el objeto JDB-1,
  `Content-Type: application/json` y las cinco cabeceras HMAC del contrato.
  La firma cubre los bytes originales de la respuesta con el método y la ruta
  de la consulta (`GET`, `/task`), el KEY_ID fijo `gateway-dev` y una ventana
  de ±60 s. El cuerpo tiene un máximo de 512 bytes. El gateway conserva el
  cuerpo byte por byte y genera un nonce nuevo para cada reentrega.
- `POST /ack` envía `device_id`, `command_id` y `status: ACKED` antes de
  ejecutar. `POST /result` envía `device_id`, `command_id`, `status` y
  `data` después de guardar el resultado. Las tres consultas llevan Bearer
  y `X-Device-ID`. El gateway debe aceptar con 2xx los ACK y RESULT repetidos
  para el mismo dispositivo y comando.
- El cliente solo ejecuta `GET_STATUS`, `GET_BATTERY` y `GET_NETWORK` con
  `payload: {}` y `requires_approval: false`. Valida el UUID, el origen,
  el destinatario y los segundos Unix de emisión y caducidad. Vuelve a
  comprobar `expires_at` tras el ACK y antes de ejecutar. El sondeo funciona
  en primer plano y duplica la espera de 5 s hasta un máximo de 60 s cuando
  la cola está vacía o hay errores. Una entrega completada restablece 5 s.
- El registro local guarda el nonce durante al menos 180 s y reserva de
  forma atómica el UUID antes de la lectura de telemetría. Si se interrumpe
  tras la reserva y antes de guardar el resultado, una reentrega vigente
  devuelve `interrupted`. Los resultados guardados se reutilizan ante una
  reentrega vigente idéntica. Los UUID anteriores al cambio, si aparecen en
  el registro legado, se rechazan para evitar volver a ejecutar esas órdenes.

### Aplazamiento de pinning TLS

Para la PoC en LAN controlada se conserva HTTPS con la validación de
certificado y nombre de host de iOS, y se rechazan todas las redirecciones.
Esto permite probar el contrato de entrega mientras se acuerdan el certificado
y su rotación, sin anclar un certificado temporal. El gateway de la PoC debe
presentar un certificado que iOS ya considere de confianza para su nombre.
El riesgo residual es que la sesión acepta cualquier cadena de confianza
válida para ese nombre, por lo que HMAC protege la orden pero la exposición
del Bearer sigue dependiendo de TLS. El aplazamiento se limita al laboratorio
con credenciales de desarrollo.

### Vectores locales

Ejecuta `python verify_jdb1.py` desde la raíz del payload. El programa valida
el V1 publicado y el flujo de entrega del perfil con un modelo Python y un
reloj fijo. La compilación, la ejecución de Swift en iOS y la interoperabilidad
con el gateway requieren las comprobaciones en macOS y en el laboratorio.

