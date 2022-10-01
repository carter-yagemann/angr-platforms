import os

import angr
import angr_platforms.riscv64


def test_hello_world():
    bin_fp = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_programs/riscv64/program.elf'))

    proj = angr.Project(bin_fp)

    ss = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(ss)

    simgr.explore(find=0x10564)

    assert len(simgr.found) == 1


def main():
    test_hello_world()


if __name__ == '__main__':
    main()
