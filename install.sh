#!/bin/sh
# Установка и обновление xsub на роутере Keenetic (Entware + XKeen с ядром Xray).
#
#   curl -fsSL https://raw.githubusercontent.com/furriest/xsub/main/install.sh | sh
#
# Переменные:
#   XSUB_VERSION=v0.2.0  — конкретная версия (по умолчанию последняя)
#   XSUB_FEED=1          — подключить репозиторий opkg, чтобы обновляться через «opkg upgrade»
#   XSUB_YES=1           — без вопросов: если нет XKeen или ядра Xray, установить их
set -e

REPO="${XSUB_REPO:-furriest/xsub}"
TMP=/opt/tmp/xsub.ipk

say() { echo "xsub: $*"; }
die() { echo "xsub: $*" >&2; exit 1; }

# ask "вопрос" — да/нет с клавиатуры (скрипт обычно идёт через «curl | sh», поэтому читаем /dev/tty).
# Без терминала (ssh без -t, cron) — «нет»: ничего не ставим без спроса. XSUB_YES=1 — «да» на всё.
ask() {
  [ "$XSUB_YES" = "1" ] && return 0
  [ "$TTY" = /dev/tty ] || return 1
  printf 'xsub: %s [Д/н] ' "$1" > /dev/tty
  read -r ans < /dev/tty || return 1
  case "$ans" in n*|N*|н*|Н*) return 1 ;; esac
  return 0
}
running() { for d in /proc/[0-9]*; do [ "$(cat "$d/comm" 2>/dev/null)" = "$1" ] && return 0; done; return 1; }
XKEEN_URL=https://raw.githubusercontent.com/jameszeroX/XKeen/main/install.sh
TTY=/dev/null
{ [ -r /dev/tty ] && : < /dev/tty; } 2>/dev/null && TTY=/dev/tty

command -v opkg >/dev/null 2>&1 || die "не найден opkg — нужен Entware (Keenetic: компонент «Поддержка открытых пакетов»)."

case "$(uname -m)" in
  aarch64|arm64) ARCH=aarch64 ;;
  armv7*|armv6*|armv5*) ARCH=armv7 ;;
  mips*)
    if opkg print-architecture 2>/dev/null | grep -q mipsel; then
      ARCH=mipsel
    elif opkg print-architecture 2>/dev/null | grep -q 'mips'; then
      ARCH=mips
    else
      die "не удалось определить порядок байт MIPS (opkg print-architecture)."
    fi
    ;;
  *) die "архитектура $(uname -m) не поддерживается." ;;
esac

# ---------- свободное место ----------
# Ядро Xray занимает около 33 МБ, geo-базы ещё 6, xsub 8, XKeen с зависимостями 3-5.
# На встроенном хранилище Keenetic (обычно раздел на 55 МБ под OPKG) это не помещается.
# Без предупреждения человек узнаёт об этом в середине установки, с половиной пакетов на диске.
# Поле «Available» берём с конца строки: при длинном имени устройства busybox df переносит её.
# Если df нет или он промолчал, возвращаем 0 — проверка тогда просто пропускается,
# а не роняет установку (скрипт идёт под set -e).
free_kb() { df -k "$1" 2>/dev/null | awk 'END { if (NF >= 3) print $(NF-2)+0; else print 0 }'; }

FREE=$(free_kb /opt)
if [ -x /opt/sbin/xray ]; then
  NEED=20480    # ядро уже стоит — считаем только на сам xsub с запасом на распаковку
else
  NEED=102400   # ставим всё с нуля
fi
if [ "$FREE" -gt 0 ] && [ "$FREE" -lt "$NEED" ]; then
  say "свободно $((FREE / 1024)) МБ, нужно около $((NEED / 1024)) МБ."
  if [ ! -x /opt/sbin/xray ]; then
    say "ядро Xray занимает ~33 МБ, geo-базы ~6 МБ, xsub ~8 МБ, XKeen с зависимостями 3-5 МБ."
    say "встроенного хранилища Keenetic для этого не хватает — перенесите Entware на USB-накопитель."
  fi
  ask "Всё равно продолжить?" || die "установка отменена: мало места."
fi

if [ -n "$XSUB_VERSION" ]; then
  URL="https://github.com/$REPO/releases/download/$XSUB_VERSION/xsub_$ARCH.ipk"
else
  URL="https://github.com/$REPO/releases/latest/download/xsub_$ARCH.ipk"
fi

mkdir -p /opt/tmp
say "скачиваю $URL"
if command -v curl >/dev/null 2>&1; then
  curl -fL --retry 3 -o "$TMP" "$URL" || die "не удалось скачать пакет."
elif command -v wget >/dev/null 2>&1; then
  wget -O "$TMP" "$URL" || die "не удалось скачать пакет (установите curl: opkg install curl)."
else
  die "нужен curl: opkg install curl"
fi

# ---------- XKeen и ядро Xray ----------
# xsub только наполняет конфиги Xray; перехватывает трафик и запускает ядро XKeen.
if [ ! -x /opt/sbin/xkeen ]; then
  say "XKeen не установлен — без него трафик устройств не попадёт в Xray."
  if ask "Установить XKeen сейчас? (в его установщике выберите ядро Xray)"; then
    opkg update && opkg install curl tar || die "не удалось установить curl и tar."
    curl -fsSL "$XKEEN_URL" -o /opt/tmp/xkeen-install.sh || die "не удалось скачать установщик XKeen."
    # без терминала (XSUB_YES=1) — автоустановка XKeen только с ядром Xray
    [ "$TTY" = /dev/tty ] || sed -i 's#^exec /opt/sbin/xkeen -i$#exec /opt/sbin/xkeen -i auto cores=xray#' /opt/tmp/xkeen-install.sh
    (cd /tmp && sh /opt/tmp/xkeen-install.sh < "$TTY") || say "установщик XKeen завершился с ошибкой — xsub ставлю, XKeen доустановите позже."
    rm -f /opt/tmp/xkeen-install.sh
  else
    say "XKeen можно поставить позже:"
    say "  opkg update && opkg install curl tar && sh -c \"\$(curl -sSL $XKEEN_URL)\""
  fi
fi
if [ -x /opt/sbin/xkeen ]; then
  if [ ! -x /opt/sbin/xray ]; then
    say "у XKeen нет ядра Xray."
    if ask "Установить Xray (xkeen -ux auto)?"; then
      /opt/sbin/xkeen -ux auto || say "не получилось — выполните вручную: xkeen -ux"
    else
      say "установите позже: xkeen -ux"
    fi
  fi
  if [ -x /opt/sbin/xray ] && running mihomo && ! running xray; then
    say "XKeen сейчас работает на ядре mihomo, а xsub управляет только Xray."
    if ask "Переключить XKeen на Xray (xkeen -xray)?"; then
      /opt/sbin/xkeen -xray < "$TTY" || say "не получилось — выполните вручную: xkeen -xray"
    else
      say "переключить можно позже: xkeen -xray"
    fi
  fi
fi

opkg install "$TMP"
rm -f "$TMP"

if [ "$XSUB_FEED" = "1" ]; then
  OWNER="${REPO%%/*}"
  NAME="${REPO#*/}"
  echo "src/gz xsub https://$OWNER.github.io/$NAME/$ARCH" > /opt/etc/opkg/xsub.conf
  say "репозиторий подключён: обновление — opkg update && opkg upgrade xsub"
fi
