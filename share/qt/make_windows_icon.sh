#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/electriccoin.ico

convert ../../src/qt/res/icons/electriccoin-16.png ../../src/qt/res/icons/electriccoin-32.png ../../src/qt/res/icons/electriccoin-48.png ${ICON_DST}
