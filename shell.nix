{ pkgs ? import <nixpkgs> {}}:

pkgs.mkShell rec {
  name = "impure-python-venv";

  # Required by venvShellHook script
  venvDir = "./.venv";

  # build-time dependencies
  buildInputs = with pkgs; [
    python39Full

    graphviz

    # Triggers the .venv after entering the shell.
    python39Packages.venvShellHook
  ];

  # Runtime dependencies
  propagatedBuildInputs = [
    # This contains most of the .so for building python libraries such as pandas
#    pythonManylinuxPackages.manylinux2014Package
  ];

  # Add .so to the linker path
  #LD_LIBRARY_PATH = "${pkgs.pythonManylinuxPackages.manylinux2014Package}/lib";

  postShellHook = ''
    pip install -q -r requirements.txt
  '';
}
