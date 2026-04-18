#!/bin/bash

sudo apt-get install fuse -y

cp -r linux64 nekoslop.AppDir

# The file for Appimage

rm nekoslop.AppDir/launcher

cat >nekoslop.AppDir/nekoslop.desktop <<-EOF
[Desktop Entry]
Name=nekoslop
Exec=echo "nekoslop started"
Icon=nekoslop
Type=Application
Categories=Network
EOF

cat >nekoslop.AppDir/AppRun <<-EOF
#!/bin/bash
echo "PATH: \${PATH}"
echo "nekoslop runing on: \$APPDIR"
LD_LIBRARY_PATH=\${APPDIR}/usr/lib QT_PLUGIN_PATH=\${APPDIR}/usr/plugins \${APPDIR}/nekoslop -appdata "\$@"
EOF

chmod +x nekoslop.AppDir/AppRun

# build

curl -fLSO https://github.com/AppImage/AppImageKit/releases/latest/download/appimagetool-x86_64.AppImage
chmod +x appimagetool-x86_64.AppImage
./appimagetool-x86_64.AppImage nekoslop.AppDir

# clean

rm appimagetool-x86_64.AppImage
rm -rf nekoslop.AppDir
