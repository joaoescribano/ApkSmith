import argparse
import os
import shutil
from .apk_smith import ApkSmith

def main():
    parser = argparse.ArgumentParser(description='APKSmith Tool')
    parser.add_argument('bundle_id', type=str, help='APK bundle id')
    parser.add_argument('--device_id', type=str, required=False, help='ADB Device ID to download the APK from, if not provided, the first connected device to ADB will be used')
    parser.add_argument('--keystore_path', type=str, required=False, help='Path to your keystore file, if not provided, a new keystore will be generated for you')
    parser.add_argument('--keystore_alias', type=str, required=False, help='Alias for the keystore (Required if --keystore_path is provided)')
    parser.add_argument('--keystore_pass', type=str, required=False, help='Password for the keystore (Required if --keystore_path is provided)')
    parser.add_argument('--key_pass', type=str, required=False, help='Password for the key (Required if --keystore_path is provided)')
    parser.add_argument('--output_dir', type=str, required=False, default="./output", help='Directory to store final APK files, default is ./output')
    parser.add_argument('--zipalign_path', type=str, required=False, default="zipalign", help='Path to the zipalign tool, default is zipalign in PATH')
    parser.add_argument('--apksigner_path', type=str, required=False, default="apksigner", help='Path to the apksigner tool, default is apksigner in PATH')
    parser.add_argument('--apktool_path', type=str, required=False, default="apktool", help='Path to the apktool, default is apktool in PATH')
    parser.add_argument('--replace_cert', '-rc', action='store_true', default=False, help='Replace the certificate of the APK file')
    parser.add_argument('--network-security-by-pass', '-nsb', action='store_true', default=False, help='Bypass network security config')
    args = parser.parse_args()

    if args.keystore_path and not args.keystore_alias:
        parser.error("--keystore_alias is required when --keystore_path is provided")
    if args.keystore_path and not args.keystore_pass:
        parser.error("--keystore_pass is required when --keystore_path is provided")
    if args.keystore_path and not args.key_pass:
        parser.error("--key_pass is required when --keystore_path is provided")

    apk_smith = ApkSmith(
        bundle_id=args.bundle_id,
        device_id=args.device_id,
        keystore_path=args.keystore_path,
        keystore_alias=args.keystore_alias,
        keystore_pass=args.keystore_pass,
        key_pass=args.key_pass,
        output_dir=args.output_dir,
        zipalign_path=args.zipalign_path,
        apksigner_path=args.apksigner_path,
        apktool_path=args.apktool_path
    )

    apk_smith.validate_dependencies()
    apk_smith.isAdbDeviceConnected()

    apk_files = apk_smith.download_apk()
    if not apk_files or len(apk_files) == 0:
        raise RuntimeError("Failed to download APK file")

    final_dir = os.path.join(args.output_dir, "final")
    os.makedirs(final_dir, exist_ok=True)

    final_apk_files = []
    for apk_file in apk_files:
        apk_file_name = os.path.basename(apk_file)
        final_apk_path = os.path.join(final_dir, apk_file_name)
        shutil.copy(apk_file, final_apk_path)
        final_apk_files.append(final_apk_path)

    if args.network_security_by_pass:
        apk_smith.bypass_network_security(final_apk_files)

    apk_smith.apply_zipalign(final_apk_files)
    apk_smith.sign_apk(final_apk_files)

if __name__ == '__main__':
    main()