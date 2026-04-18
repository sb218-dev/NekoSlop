# NekoSlop

<div align="center">

![NekoSlop Logo](res/icons/nekoslop.png)

**Быстрый и мощный прокси-клиент на базе sing-box для Windows**

[![Оригинальный форк](https://img.shields.io/badge/Based%20on-NekoRay%2FNekoBox-blueviolet?style=for-the-badge)](https://github.com/Matsuridayo/nekoray/releases)
[![sing-box](https://img.shields.io/badge/Core-sing--box%201.9.7-blue?style=for-the-badge)](https://github.com/SagerNet/sing-box)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-lightgrey?style=for-the-badge)](https://github.com/Matsuridayo/nekoray)

</div>

---

## О проекте

**NekoSlop** — форк проекта [NekoRay / NekoBox for PC](https://github.com/Matsuridayo/nekoray/releases) с улучшениями и адаптацией для русскоязычной аудитории.  
Ядро обновлено до **sing-box 1.9.7-neko-1** с поддержкой протоколов VLESS Reality, Hysteria2, TUIC, WireGuard и других.

> **Оригинальный проект:** [https://github.com/Matsuridayo/nekoray/releases](https://github.com/Matsuridayo/nekoray/releases)  
> Авторы оригинала: Matsuridayo и участники сообщества.

---

## Поддерживаемые протоколы

| Протокол | Поддержка |
|---|---|
| VLESS + Reality / XTLS | ✅ |
| VMess | ✅ |
| Trojan | ✅ |
| ShadowSocks 2022 | ✅ |
| Hysteria2 | ✅ |
| TUIC v5 | ✅ |
| WireGuard | ✅ |
| SOCKS5 / HTTP | ✅ |
| Naive | ✅ |

---

## Что изменено в NekoSlop

### 🔧 Обновление ядра
- **sing-box** обновлён с 1.8.x до **1.9.7-neko-1**
- Добавлен флаг `-checklinkname=0` для совместимости с Go 1.22+
- Обновлены зависимости: `sing`, `sing-tun`, `sing-quic`, `sing-dns`

### 🎨 Интерфейс
- Убраны кнопки «Реклама», «Документация» и «Обновление» из тулбара
- Режим TUN включается **автоматически** при старте приложения
- В диалоге настройки маршрута добавлена вкладка **«Приложения»** — визуальный выбор процессов для проксирования прямо из списка установленных программ

### 🌐 Подписки и Протоколы
- Добавлена встроенная поддержка нового транспорта `xhttp` (он же `httpupgrade` в старых Xray), который автоматически конвертируется для совместимости с ядром sing-box 1.9+.
- User-Agent изменён на `HiddifyNG/2.0.5 ClashMeta` для совместимости с большинством провайдеров (включая moonshard.org, Bird VPN и др.)
- Добавлено автоопределение подписок по пути `/sub/`

### 🛡️ TUN / DPI-обход
- Исправлена критическая проблема с зацикливанием DNS (ошибка `context deadline exceeded`), возникавшая при работе TUN в связке с системным резолвером Windows.
- В конфиг TUN-режима добавлены исключения для `winws.exe` (Zapret) и `goodbyedpi.exe`
- Включён sniffing трафика для корректного маршрутирования

### 📦 Сборка
- Автоматические скрипты `install_env.ps1` и `build.ps1`
- Поддержка Qt 6.5 + MSVC 2022 Build Tools
- Конфигурация sing-box обновлена для совместимости с новым API

---

### 🚀 Новое в этой версии

- **Двусторонняя синхронизация**: Теперь выбор приложений в UI и JSON-правила полностью синхронизированы. Если вы выбираете приложение в списке, оно автоматически добавляется в JSON с высшим приоритетом.
- **Поддержка Xray xhttp**: Добавлена поддержка транспорта `xhttp` (h2), который теперь корректно мапится на ядро sing-box.
- **Исправлен DNS Loop**: Больше нет бесконечных циклов DNS при использовании TUN режима.
- **Инсталлятор**: Полноценный `.exe` установщик с корректной настройкой прав доступа.

---

---

## Быстрый старт

1. Скачайте инсталлер `NekoSlopSetup.exe` из раздела [Releases](../../releases)
2. Установите и запустите NekoSlop — приложение **запросит права администратора** (необходимо для TUN-режима)
3. Добавьте подписку через меню **Сервер → Добавить профиль из буфера обмена** или вставьте ссылку напрямую
4. Выберите профиль и нажмите Enter — соединение установится автоматически в режиме TUN

---

## Настройка маршрутизации

Откройте **Настройки → Настройки маршрута**:

- **Прокси / Прямое / Блок** — домены и IP по категориям (geoip:ru, geosite:category-ads-all и т.д.)
- **Приложения** *(новая вкладка)* — визуальный выбор приложений на вашем ПК для принудительного проксирования

---

## Системные требования

- Windows 10 / 11 (x64)
- Права администратора (для TUN-режима)
- Visual C++ Redistributable 2022 (включён в инсталлер)

---

## Сборка из исходников

```powershell
# Требования: Qt 6.5, MSVC 2022, Go 1.22+, Git
.\install_env.ps1   # только первый раз
.\build.ps1
```

Готовый бинарник появится в папке `build/`.

---

## Лицензия

Проект распространяется под той же лицензией, что и оригинальный [NekoRay](https://github.com/Matsuridayo/nekoray) — **GPL-3.0**.  
Ядро [sing-box](https://github.com/SagerNet/sing-box) — **GPL-3.0**.

---

<div align="center">

Сделано с ❤️ на основе [NekoRay / NekoBox for PC](https://github.com/Matsuridayo/nekoray/releases)

</div>
