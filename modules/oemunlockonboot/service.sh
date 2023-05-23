exec >/data/local/tmp/avbroot_oem_unlock.log 2>&1

mod_dir=${0%/*}

header() {
    echo "----- ${*} -----"
}

header Environment
echo "Timestamp: $(date)"
echo "Script: ${0}"
echo "UID/GID/Context: $(id)"

header Enable OEM unlocking
CLASSPATH="${mod_dir}/classes.dex" app_process / Main &
pid=${!}
wait "${pid}"
echo "Exit status: ${?}"
echo "Logcat:"
logcat -d --pid "${pid}"
