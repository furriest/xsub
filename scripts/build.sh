#!/usr/bin/env bash
# Сборка xsub под роутеры Keenetic (Entware) и упаковка в .ipk.
#
#   VERSION=0.2.0 scripts/build.sh
#
# Результат в dist/:
#   xsub_<arch>.ipk               — пакеты для релиза на GitHub (имя без версии,
#                                   чтобы работала ссылка releases/latest/download/…)
#   xsub-<version>-<arch>         — голые бинарники
#   repo/<arch>/Packages(.gz)     — репозиторий opkg (для GitHub Pages)
#   SHA256SUMS
set -euo pipefail

cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null | sed 's/^v//' || true)}"
VERSION="${VERSION:-0.0.0}"
OUT="${OUT:-dist}"
REPO="${REPO:-furriest/xsub}"   # владелец/репозиторий на GitHub
DESC="Подписки (ссылки, Clash, sing-box, JSON Xray), списки доменов и сторож узлов для XKeen + Xray"

# arch  GOARCH  GOMIPS     GOARM
TARGETS=(
  "x86_64  amd64  -          -"
  "aarch64 arm64  -          -"
  "mipsel  mipsle softfloat  -"
  "mips    mips   softfloat  -"
  "armv7   arm    -          5"
)

rm -rf "$OUT"
mkdir -p "$OUT/repo"

for t in "${TARGETS[@]}"; do
  read -r arch goarch gomips goarm <<<"$t"
  echo ">> $arch"
  bin="$OUT/xsub-$VERSION-$arch"
  env CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
    $( [ "$gomips" != "-" ] && echo GOMIPS="$gomips" ) \
    $( [ "$goarm" != "-" ] && echo GOARM="$goarm" ) \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION -X main.defaultRepo=$REPO" -o "$bin" .

  work="$(mktemp -d)"
  mkdir -p "$work/data/opt/sbin" "$work/data/opt/etc/init.d" "$work/control"
  install -m 0755 "$bin" "$work/data/opt/sbin/xsub"
  install -m 0755 packaging/S99xsub "$work/data/opt/etc/init.d/S99xsub"
  size=$(du -sb "$work/data" | cut -f1)

  cat > "$work/control/control" <<EOF
Package: xsub
Version: $VERSION
Depends:
Source: https://github.com/$REPO
License: MIT
Section: net
Architecture: all
Installed-Size: $size
Maintainer: xsub
Description: $DESC
EOF
  # В postinst есть ссылка на репозиторий — подставляем так же, как в install.sh.
  sed "s#OWNER/xsub#$REPO#g" packaging/postinst > "$work/control/postinst"
  chmod 0755 "$work/control/postinst"
  install -m 0755 packaging/prerm "$work/control/prerm"

  tar_opts=(--format=gnu --numeric-owner --owner=0 --group=0 --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}")
  (cd "$work/data" && tar "${tar_opts[@]}" -czf ../data.tar.gz .)
  (cd "$work/control" && tar "${tar_opts[@]}" -czf ../control.tar.gz .)
  echo "2.0" > "$work/debian-binary"
  ipk="$OUT/xsub_${arch}.ipk"
  (cd "$work" && tar "${tar_opts[@]}" -czf pkg.ipk ./debian-binary ./data.tar.gz ./control.tar.gz)
  mv "$work/pkg.ipk" "$ipk"

  # Репозиторий opkg: отдельная папка на архитектуру.
  feed="$OUT/repo/$arch"
  mkdir -p "$feed"
  fname="xsub_${VERSION}_${arch}.ipk"
  cp "$ipk" "$feed/$fname"
  {
    grep -v '^Description:' "$work/control/control"
    echo "Filename: $fname"
    echo "Size: $(stat -c %s "$feed/$fname")"
    echo "SHA256sum: $(sha256sum "$feed/$fname" | cut -d' ' -f1)"
    echo "Description: $DESC"
    echo
  } > "$feed/Packages"
  gzip -9nc "$feed/Packages" > "$feed/Packages.gz"
  rm -rf "$work"
done

sed "s#OWNER/xsub#$REPO#g" install.sh > "$OUT/repo/install.sh"
cp "$OUT/repo/install.sh" "$OUT/install.sh"
(cd "$OUT" && sha256sum xsub_*.ipk xsub-*-* install.sh > SHA256SUMS)
echo "Готово: $OUT/"
ls -la "$OUT"
