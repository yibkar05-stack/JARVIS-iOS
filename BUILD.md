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

## Adaptador JDB-1 pendiente de cotejo

El directorio de ejecución carecía de la especificación de Fase 2. El
adaptador provisional vive en `App/Agent.swift`. Usa la URL base HTTPS
introducida en la app. Envía `Authorization: Bearer <credencial>` y
`X-Device-ID: JARVIS-IP8-001` a las rutas relativas `GET commands` y
`POST results`. El GET acepta 204 o un objeto JSON con `command_id`,
`command` e `issued_at` (ISO 8601). El POST envía `command_id`,
`status` y `data`, y espera 2xx. Hay que cotejar rutas, autenticación,
esquemas, respuestas y acuse idempotente con el contrato antes de conectar
la app al gateway.

La pantalla permite configurar manualmente la URL y guardar la credencial
del dispositivo en Keychain. El sondeo es optativo y se ejecuta en primer
plano. El cliente admite `GET_STATUS`, `BATTERY` y `NETWORK`, verifica la
vigencia de 120 segundos contra el reloj del dispositivo y guarda el
resultado por URL e ID para reutilizarlo si vuelve a recibir la misma orden
vigente. El gateway debe deduplicar la recepción de resultados por ID.

## Estado de esta entrega

La ejecución fue local en Windows. La búsqueda de `xcodebuild` y `swift`
mediante `Get-Command` no devolvió ejecutables. La instrucción de ejecución
local excluyó GitHub y cualquier servicio externo. Quedan pendientes la
compilación en macOS, la prueba de reproducibilidad, la obtención del IPA
y su SHA-256, y el cotejo con Fase 2. El estado de facturación de GitHub
quedó sin verificar.
