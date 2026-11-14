# SPDX-FileCopyrightText: 2026 StarHub Contributors
# SPDX-License-Identifier: MIT
{
  description = "StarHub Kit — Zero-dependency declarative compiler for multi-site Tailscale 4via6 routing, deterministic Mihomo split-DNS/QUIC governance, and cloud AI sandbox dual-stack firewalls";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.stdenvNoCC.mkDerivation {
            pname = "starhub-kit";
            version = "1.3.0";
            src = self;
            dontBuild = true;
            installPhase = ''
              runHook preInstall
              mkdir -p $out/share/starhub-kit $out/bin
              cp -R . $out/share/starhub-kit/
              cat > $out/bin/starhub <<EOF
              #!${pkgs.bash}/bin/bash
              set -euo pipefail
              exec ${pkgs.python3}/bin/python3 "$out/share/starhub-kit/scripts/starhub-ctl.py" --repo-root "$out/share/starhub-kit" "\$@"
              EOF
              chmod +x $out/bin/starhub
              runHook postInstall
            '';
            meta = with pkgs.lib; {
              description = "Zero-dependency declarative compiler for multi-site Tailscale mesh, split-DNS/QUIC gateways, and AI sandbox firewalls";
              homepage = "https://github.com/Ziqi/starhub-kit";
              license = licenses.mit;
              mainProgram = "starhub";
              platforms = platforms.unix;
            };
          };
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/starhub";
        };
      });

      checks = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          starhub-verify = pkgs.runCommand "starhub-kit-verify" { src = self; } ''
            cp -R $src ./work
            chmod -R u+w ./work
            ${pkgs.python3}/bin/python3 ./work/scripts/starhub-ctl.py --repo-root ./work render --check
            ${pkgs.python3}/bin/python3 ./work/scripts/starhub-ctl.py --repo-root ./work archive --verify
            ${pkgs.python3}/bin/python3 ./work/tests/fuzz_starhub_ctl.py --iterations 200
            touch $out
          '';
        });
    };
}
