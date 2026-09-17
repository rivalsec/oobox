"""oobox CLI:  python -m oobox <serve|selftest|genkey|check>."""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys

from .config import Config, new_api_key


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def cmd_serve(args) -> int:
    config = Config.from_env()
    if args.domain:
        config.domain = args.domain.rstrip(".").lower()
    if args.ipv4:
        config.ipv4 = args.ipv4
    problems = config.validate()
    if problems:
        print("Refusing to start — fix configuration:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 2

    async def main():
        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:
                pass
        from .server import Server
        server = Server(config)
        await server.start()
        logging.getLogger("oobox").info("oobox up for zone %s — ctrl-c to stop", config.domain)
        await stop.wait()
        await server.stop()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except OSError as e:
        print(f"Failed to start: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_selftest(args) -> int:
    from .selftest import run_selftest
    ok = asyncio.run(run_selftest())
    return 0 if ok else 1


def cmd_genkey(args) -> int:
    print(new_api_key())
    return 0


def cmd_check(args) -> int:
    config = Config.from_env()
    problems = config.validate()
    print(f"env file    : {getattr(args, '_env_loaded', None) or 'none (using OS env only)'}")
    print(f"domain      : {config.domain}")
    print(f"ipv4 / ipv6 : {config.ipv4} / {config.ipv6}")
    print(f"nameservers : {config.nameservers}")
    print(f"ports       : dns={config.dns_port} http={config.http_port} "
          f"https={config.https_port} smtp={config.smtp_port} api={config.api_port}")
    print(f"tls (http)  : {'on' if config.http_tls() else 'off'}")
    print(f"api tls     : {'on' if config.api_tls() else 'off (plaintext!)'}")
    print(f"api allow   : {config.api_allow or 'ANY (set OOB_API_ALLOW!)'}")
    print(f"retention   : {config.ttl_days} days")
    from .tokens import PREFIX, clamp_len
    eff = clamp_len(config.token_len)
    print(f"token len   : {PREFIX}+{eff} chars"
          + (f"  (OOB_TOKEN_LEN={config.token_len} clamped to {eff})" if eff != config.token_len else ""))
    print(f"smtp send   : {'on' if config.smtp_send else 'off'}"
          f"{' via ' + config.smtp_relay if config.smtp_relay else ' (direct-to-MX)' if config.smtp_send else ''}")
    tg = "on" if (config.tg_token and config.tg_chat) else "off"
    print(f"tg alerts   : {tg}"
          + (f" (window={config.alert_window:g}s, kinds={','.join(config.alert_kinds)}, "
             f"proxy={config.tg_proxy or 'none'})" if tg == "on" else ""))
    if problems:
        print("\nPROBLEMS:")
        for p in problems:
            print(f"  - {p}")
        return 2
    print("\nconfig OK")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="oobox", description=__doc__)
    ap.add_argument("--log", default="info", help="log level (debug/info/warning/error)")
    ap.add_argument("--env-file", help="load config from this .env (default: ./.env, then "
                                       "./deploy/.env, or $OOB_ENV_FILE; --env-file=none to skip)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve", help="run all listeners (needs OOBDOMAIN, OOB_IPV4, OOB_API_KEY)")
    p.add_argument("--domain", help="override OOBDOMAIN")
    p.add_argument("--ipv4", help="override OOB_IPV4")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("selftest", help="run the full end-to-end local selftest")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("genkey", help="print a fresh control-API bearer key")
    p.set_defaults(func=cmd_genkey)

    p = sub.add_parser("check", help="print the effective config and validate it")
    p.set_defaults(func=cmd_check)

    args = ap.parse_args(argv)
    _setup_logging(args.log)
    if args.env_file != "none":
        from .config import autoload_env
        loaded = autoload_env(args.env_file)
        args._env_loaded = loaded
        if loaded:
            logging.getLogger("oobox").info("loaded config from %s", loaded)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
