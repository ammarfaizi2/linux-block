#!/bin/sh

./mv-dts

for files in $(ls arch/arm/boot/dts/*.dtsi); do
	f=$(basename $files)
	git grep -l -F "$f" arch/arm/boot/dts | xargs perl -p -i -e "s/$f/..\/$f/"
	git add $files
done

git grep -l -F "arm/uniphier" arch/arm64/boot/dts | xargs perl -p -i -e "s/arm\/uniphier/arm\/socionext\/uniphier/"
git grep -l -F "arm/sunxi" arch/arm64/boot/dts | xargs perl -p -i -e "s/arm\/sunxi/arm\/allwinner\/sunxi/"
git grep -l -F "arm/bcm" arch/arm64/boot/dts | xargs perl -p -i -e "s/arm\/bcm/arm\/brcm\/bcm/"
git grep -l -F "vexpress-v2m-rs1" arch/arm64/boot/dts | xargs perl -p -i -e "s/vexpress-v2m-rs1/arm\/arm\/vexpress-v2m-rs1/"
git add arch/arm64/boot/dts/
