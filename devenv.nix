{ pkgs, config, ... }:

{
  # https://devenv.sh/basics/
  env.GREET = "devenv";

  # https://devenv.sh/packages/
  packages = [
    pkgs.openssl
    pkgs.gcc
  ];

  # https://devenv.sh/languages/
  # languages.nix.enable = true;
  languages = {
    python.enable = true;
  };

  certificates = [
    "purple.localhost"
  ];

  services.caddy = {
    enable = true;
    virtualHosts."purple.localhost" = {
      extraConfig = ''
        reverse_proxy :3000
      '';
    };
  };

}
