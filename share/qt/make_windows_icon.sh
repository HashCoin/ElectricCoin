#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/soccercoin.ico

convert ../../src/qt/res/icons/soccercoin-16.png ../../src/qt/res/icons/soccercoin-32.png ../../src/qt/res/icons/soccercoin-48.png ${ICON_DST}
