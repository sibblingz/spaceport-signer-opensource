#!/bin/bash -xe

# NOTE: $WORKSPACE is the root of the job directory

STAGING_AREA="$1"
CERTS_DIR="$2"

#nuke the workspace
rm -rf $WORKSPACE/*

#remove job status flag
rm -f $STAGING_AREA/status/$JOB_NAME.succeeded

#copy new spaceportapp to workspace
#cp -R $STAGING_AREA/workspace/ios/release/spaceportappnolib.app $WORKSPACE/
cp -R $STAGING_AREA/workspace/sdk/osx/package/lib/spaceport-support/ios/unsigned-ios-rel.app $WORKSPACE/spaceportappnolib.app

#validate the unsigned app to ensure it's unsigned
$SP_SCRIPTS/cs_mutex.sh enabled "$SP_SCRIPTS/validate_file_new.sh $WORKSPACE/spaceportappnolib.app" 2>&1 | tee $WORKSPACE/results.txt
#$SP_SCRIPTS/validate_file.sh $STAGING_AREA $CERTS_DIR $WORKSPACE/spaceportappnolib.app 2>&1 | tee $WORKSPACE/results.txt

grep "Application failed codesign verification" $WORKSPACE/results.txt 2>&1 | tee $WORKSPACE/grep_results.txt

FILESIZE=$(stat -f %z $WORKSPACE/grep_results.txt)

if [ $FILESIZE -eq 0 ]; then
   echo "Expecting unsigned application."
   exit 1
fi

#sign the unsigned app
java -jar $STAGING_AREA/workspace/sdk/osx/package/lib/spaceport-support/sp-signer/sp-signer.jar \
    sign-bundle $WORKSPACE/spaceportappnolib.app \
    --mprovision $CERTS_DIR/iOS_Team_Provisioning_Profile_.mobileprovision \
    --pkcs12-pw $CERTS_DIR/CertificatesBS.p12 WhyN00t \
    2>&1 | tee $WORKSPACE/results.txt

#TBD do something with the results.txt file from signer?

#validate the signed app
#$SP_SCRIPTS/validate_file.sh $STAGING_AREA $CERTS_DIR $WORKSPACE/spaceportappnolib.app 2>&1 | tee $WORKSPACE/results.txt
$SP_SCRIPTS/cs_mutex.sh enabled "$SP_SCRIPTS/validate_file_new.sh $WORKSPACE/spaceportappnolib.app" 2>&1 | tee $WORKSPACE/results.txt

grep "Application failed codesign verification" $WORKSPACE/results.txt 2>&1 | tee $WORKSPACE/grep_results.txt

FILESIZE=$(stat -f %z $WORKSPACE/grep_results.txt)

if [ $FILESIZE -ne 0 ]; then
   echo "Signing failed"
   exit 1
fi

#notify results job that this test completed successfully
touch $STAGING_AREA/status/$JOB_NAME.succeeded

