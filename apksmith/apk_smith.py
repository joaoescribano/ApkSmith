import os
import subprocess
import shutil
import zipfile

class ApkSmith:
    def __init__(self, bundle_id, device_id=False, keystore_path=False, keystore_alias=False, keystore_pass=False, key_pass=False, output_dir="./output", zipalign_path="zipalign", apksigner_path="apksigner", apktool_path="apktool", keytool_path="keytool"):
        self.bundle_id = bundle_id
        self.device_id = device_id
        self.keystore_path = keystore_path
        self.keystore_alias = keystore_alias
        self.keystore_pass = keystore_pass
        self.key_pass = key_pass
        self.output_dir = output_dir
        self.zipalign_path = zipalign_path
        self.zipalign_columns = 4
        self.apksigner_path = apksigner_path
        self.apktool_path = apktool_path
        self.keytool_path = keytool_path
        self.multi_apk = False

    def setZipalignPath(self, zipalign_path):
        self.zipalign_path = zipalign_path
    
    def setApksignerPath(self, apksigner_path):
        self.apksigner_path = apksigner_path

    def validate_dependencies(self):
        dependencies = ["adb", self.zipalign_path, self.apksigner_path, self.apktool_path, self.keytool_path]
        for dep in dependencies:
            if not self._is_command_available(dep):
                raise EnvironmentError(f"Dependency {dep} is not available")

    def _is_command_available(self, command):
        return subprocess.call(f"type {command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

    def isAdbDeviceConnected(self):
        if self.device_id:
            result = subprocess.run(["adb", "-s", self.device_id, "get-state"], capture_output=True)
            if result.returncode == 0 and result.stdout.decode().strip() == "device":
                return True
            raise RuntimeError("Invalid ADB --device_id provided")
        else:
            result = subprocess.run(["adb", "devices"], capture_output=True)
            devices = result.stdout.decode().splitlines()[1:]
            for device in devices:
                if device.strip() != "":
                    self.device_id = device.split("\t")[0]
                    return True
        raise RuntimeError("No ADB device connected")

    def download_apk(self):
        apk_paths = subprocess.run(["adb", "shell", "pm", "path", self.bundle_id], capture_output=True, text=True).stdout.splitlines()
        if len(apk_paths) == 0:
            raise RuntimeError("Failed to get APK path on device")
        if len(apk_paths) > 1:
            self.multi_apk = True
            print("Multiple APKs found, downloading all of them")
        apk_files = []
        for apk_path in apk_paths:
            apk_path = apk_path.replace("package:", "")
            original_apk_dir = os.path.join(self.output_dir, "original")
            os.makedirs(original_apk_dir, exist_ok=True)
            local_apk = os.path.join(original_apk_dir, os.path.basename(apk_path))
            print(f"Downloading APK {os.path.basename(apk_path)}")
            result = subprocess.run(["adb", "pull", apk_path, local_apk], capture_output=True)
            if result.returncode != 0:
                raise RuntimeError(f"Failed to download APK: {result.stderr.decode()}")
            apk_files.append(local_apk)
        return apk_files

    def apply_zipalign(self, apk_files = []):
        if len(apk_files) == 0:
            raise RuntimeError("No APK files provided")
        
        # loop all apks files and zipalign them, then delete the files and replace the files with the aligned
        for apk_file in apk_files:
            zipaligned_apk = os.path.join(self.output_dir, f"aligned_{os.path.basename(apk_file)}")

            if os.path.exists(zipaligned_apk):
                os.remove(zipaligned_apk)

            print(f"Applying zipalign to {apk_file}")
            result = subprocess.run([self.zipalign_path, '-p', '-v', str(self.zipalign_columns), apk_file, zipaligned_apk], capture_output=True)

            if result.returncode != 0:
                raise RuntimeError(f"Zipalign failed: {result.stderr.decode()}")

            os.remove(apk_file)
            shutil.move(zipaligned_apk, apk_file)

    def sign_apk(self, zipaligned_apks):
        # Check if the array of apks is already aligned
        for apk in zipaligned_apks:
            test = subprocess.run([self.zipalign_path, "-c", str(self.zipalign_columns), apk], capture_output=True)
            if test.returncode != 0:
                raise RuntimeError(f"APK {apk} is not aligned")

        if not self.keystore_path:
            # create a keystore for the aplication if not provided
            self.keystore_path = os.path.join(self.output_dir, "keystore.keystore")
            if os.path.exists(self.keystore_path):
                os.remove(self.keystore_path)
            self.keystore_alias = "apksmith"
            self.keystore_pass = "apksmith"
            self.key_pass = "apksmith"

            print(f"Creating keystore at {self.keystore_path}")
            print(f"Key alias: {self.keystore_alias}")
            print(f"Keystore password: {self.keystore_pass}")
            print(f"Key password: {self.key_pass}")

            result = subprocess.run([
                self.keytool_path, "-genkey", "-v",
                "-keystore", self.keystore_path,
                "-alias", self.keystore_alias,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "10000",
                "-storepass", self.keystore_pass,
                "-keypass", self.key_pass,
                "-dname", "CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, S=Unknown, C=Unknown"
            ], capture_output=True)

            if result.returncode != 0:
                raise RuntimeError(f"Failed to create keystore: {result.stderr.decode()}")
        
        for apk in zipaligned_apks:
            signed_apk = os.path.join(self.output_dir, f"signed_{os.path.basename(apk)}")
            print(f"Signing APK {apk}")

            result = subprocess.run([
                self.apksigner_path, "sign",
                "--ks", self.keystore_path,
                "--ks-key-alias", self.keystore_alias,
                "--ks-pass", f"pass:{self.keystore_pass}",
                "--key-pass", f"pass:{self.key_pass}",
                "--out", signed_apk,
                apk
            ], capture_output=True)

            if result.returncode != 0:
                raise RuntimeError(f"Signing failed: {result.stderr.decode()}")
            
            os.remove(apk)
            os.remove(f"{signed_apk}.idsig")
            shutil.move(signed_apk, apk)

    def bypass_network_security(self, apks_path):
        apk_with_manifest = []
        for apk in apks_path:
            with zipfile.ZipFile(apk, "r") as zip_ref:
                for file in zip_ref.namelist():
                    if file == "AndroidManifest.xml":
                        apk_with_manifest.append(apk)
                        break
        
        if len(apk_with_manifest) == 0:
            raise RuntimeError("No AndroidManifest.xml found in the APKs files")
        
        for apk in apk_with_manifest:
            print(f"Applying network security bypass to {apk}")
            if os.path.exists(f"{apk}_decompiled"):
                shutil.rmtree(f"{apk}_decompiled")

            result = subprocess.run([self.apktool_path, "d", apk, "-o", f"{apk}_decompiled"], capture_output=True)
            if result.returncode != 0:
                raise RuntimeError(f"Failed to decompile APK: {result.stderr.decode()}")
            
            manifest_file = f"{apk}_decompiled/AndroidManifest.xml"
            with open(manifest_file, "r") as f:
                manifest = f.read()
                if "android:networkSecurityConfig" in manifest:
                    network_secutiry_file = manifest.split("android:networkSecurityConfig=\"@xml/")[1].split("\"")[0]
                    print("Network security config already present in the manifest, patching it")

                    with open(f"{apk}_decompiled/res/xml/{network_secutiry_file}.xml", "r") as f:
                        network_security_config = f.read()

                        if "<base-config>" not in network_security_config:
                            print("Base config not found in the network security config, adding it")
                            network_security_config = network_security_config.replace("</network-security-config>", "<base-config></base-config>\n</network-security-config>")

                        if "<trust-anchors>" not in network_security_config:
                            print("Trust anchors not found in the network security config, adding it")
                            network_security_config = network_security_config.replace("</base-config>", "<trust-anchors></trust-anchors></base-config>")
                        
                        if "<certificates src=\"system\"" not in network_security_config:
                            print("System certificates not found in the network security config, adding it")
                            network_security_config = network_security_config.replace("</trust-anchors>", "<certificates src=\"system\" /></trust-anchors>")
                        
                        if "<certificates src=\"user\"" not in network_security_config:
                            print("User certificates not found in the network security config, adding it")
                            network_security_config = network_security_config.replace("</trust-anchors>", "<certificates src=\"user\" /></trust-anchors>")
                            
                        with open(f"{apk}_decompiled/res/xml/{network_secutiry_file}.xml", "w") as f:
                            f.write(network_security_config)
                else:
                    print("Network security config not found in the manifest, creating it")
                    with open(manifest_file, "w") as f:
                        f.write(manifest.replace("<application ", "<application android:networkSecurityConfig=\"@xml/network_security_config\" "))
                    os.makedirs(f"{apk}_decompiled/res/xml", exist_ok=True)
                    with open(f"{apk}_decompiled/res/xml/network_security_config.xml", "w") as f:
                        f.write('<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n\t<base-config>\n\t\t<trust-anchors>\n\t\t\t<certificates src="system" />\n\t\t\t<certificates src="user" />\n\t\t</trust-anchors>\n\t</base-config>\n</network-security-config>')
            
            print("Recompiling the APK")
            result = subprocess.run([self.apktool_path, "b", f"{apk}_decompiled", "-o", f"{apk}_patched.apk"], capture_output=True)
            if result.returncode != 0:
                raise RuntimeError(f"Failed to recompile APK: {result.stderr.decode()}")
            
            shutil.copy(f"{apk}_patched.apk", apk)
            shutil.rmtree(f"{apk}_decompiled")
            os.remove(f"{apk}_patched.apk")
        
        return apks_path