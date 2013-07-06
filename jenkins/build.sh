#!/bin/bash -xe

# NOTE: $WORKSPACE is the root of the project git repo

STAGING_AREA="$1"

#force a clean build if indicated
if [ -d $STAGING_AREA/clean.build ]; then
   echo "Performing CLEAN build."
   git clean -fdx
else
   echo "Performing INCREMENTAL build."
fi

#clean new staging area
rm -rf $STAGING_AREA/workspace/sdk/osx/package/lib/spaceport-support/sp-signer
mkdir $STAGING_AREA/workspace/sdk/osx/package/lib/spaceport-support/sp-signer

#remove Jenkins artifacts
rm -rf $WORKSPACE/libs.zip

#save change documentation to staging area
$SP_SCRIPTS/copy_component_changes.py $WORKSPACE/../builds/$BUILD_NUMBER/changelog.xml $STAGING_AREA/changes/signer.txt

ant

#move build artifacts to new staging area
cp $WORKSPACE/sp-signer.jar $STAGING_AREA/workspace/sdk/osx/package/lib/spaceport-support/sp-signer/
cp -R $WORKSPACE/libs $STAGING_AREA/workspace/sdk/osx/package/lib/spaceport-support/sp-signer/

#recreate Jenkins artifacts
zip -r libs.zip libs

