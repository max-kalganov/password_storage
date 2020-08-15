import argparse

from storage_utils.pass_interaction_app import PassStorage

if __name__ == "__main__":

    parser = argparse.ArgumentParser('Command line parser', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-s', help='service name', type=str, default=None)
    parser.add_argument('-acc', help='account login', type=str, default=None)
    parser.add_argument('-p',
                        help='print mode. \n'
                             'default -- copy to clipboard\n'
                             'short -- only service, login and password\n'
                             'full -- all account info',
                        type=str, default=None)

    args = parser.parse_args()
    assert args.p in {'short', 'full', None}, f'{args.p} not short or full'
    if any(args.__dict__.values()):
        p = PassStorage()
        p.run_with_params(args.s, args.acc, args.p)
    else:
        p = PassStorage()
        p.run()
