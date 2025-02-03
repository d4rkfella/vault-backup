#!/bin/bash
set -e

export VAULT_TOKEN=$(< /vault/secrets/token)
DATE=$(date +%Y-%m-%d-%H-%M-%S)
SNAPSHOT_RETENTION=${SNAPSHOT_RETENTION:-7}

if ! vault operator raft snapshot save /tmp/vaultsnapshot-$DATE.snap; then
    echo "Failed to create Vault snapshot"
    exit 1
fi

if /usr/local/bin/aws --endpoint-url $S3_ENDPOINT s3 cp /tmp/vaultsnapshot-$DATE.snap s3://$S3BUCKET/; then
    rm /tmp/vaultsnapshot-$DATE.snap
    echo "Completed the backup - $DATE"
else
    echo "Failed to upload snapshot to S3"
    exit 1
fi

if [ -z "$SNAPSHOTS" ]; then
    echo "No snapshots found in S3. Exiting cleanup."
    exit 0
fi

SNAPSHOTS=$(/usr/local/bin/aws --endpoint-url $S3_ENDPOINT s3 ls s3://$S3BUCKET/ | awk '{print $4}' | grep 'vaultsnapshot-' | sort -r)

COUNT=0
for FILE in $SNAPSHOTS; do
    COUNT=$((COUNT + 1))
    if [ $COUNT -gt "$SNAPSHOT_RETENTION" ]; then
        echo "Deleting old snapshot: $FILE"
        /usr/local/bin/aws --endpoint-url $S3_ENDPOINT s3 rm "s3://$S3BUCKET/$FILE"
    fi
done
