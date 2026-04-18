#!/bin/bash

version="$1"

mkdir -p nekoslop/DEBIAN
mkdir -p nekoslop/opt
cp -r linux64 nekoslop/opt/
mv nekoslop/opt/linux64 nekoslop/opt/nekoslop
rm -rf nekoslop/opt/nekoslop/usr
rm nekoslop/opt/nekoslop/launcher

# basic
cat >nekoslop/DEBIAN/control <<-EOF
Package: nekoslop
Version: $version
Architecture: amd64
Maintainer: MatsuriDayo nekoha_matsuri@protonmail.com
Depends: libxcb-xinerama0, libqt5core5a, libqt5gui5, libqt5network5, libqt5widgets5, libqt5svg5, libqt5x11extras5, desktop-file-utils
Description: Qt based cross-platform GUI proxy configuration manager (backend: v2ray / sing-box)
EOF

cat >nekoslop/DEBIAN/postinst <<-EOF
if [ ! -s /usr/share/applications/nekoslop.desktop ]; then
    cat >/usr/share/applications/nekoslop.desktop<<-END
[Desktop Entry]
Name=nekoslop
Comment=Qt based cross-platform GUI proxy configuration manager (backend: sing-box)
Exec=sh -c "PATH=/opt/nekoslop:\$PATH /opt/nekoslop/nekoslop -appdata"
Icon=/opt/nekoslop/nekoslop.png
Terminal=false
Type=Application
Categories=Network;Application;
END
fi

setcap cap_net_admin=ep /opt/nekoslop/nekoslop_core

update-desktop-database
EOF

sudo chmod 0755 nekoslop/DEBIAN/postinst

# desktop && PATH

sudo dpkg-deb -Zxz --build nekoslop
