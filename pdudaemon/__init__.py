#!/usr/bin/python3
#
#  Copyright 2018 Remi Duraffort <remi.duraffort@linaro.org>
#                 Matt Hart <matt@mattface.org>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

import argparse
import asyncio
import contextlib
import json
import logging
from logging.handlers import WatchedFileHandler
import signal
import sys
import time

from pdudaemon.tcplistener import TCPListener
from pdudaemon.httplistener import HTTPListener
from pdudaemon.pdurunner import PDURunner
from pdudaemon.drivers.driver import PDUDriver


###########
# Constants
###########
CONFIGURATION_FILE = "/etc/pdudaemon/pdudaemon.conf"
logging_FORMAT = "%(asctime)s - %(name)-30s - %(levelname)s %(message)s"
logging_FORMAT_JOURNAL = "%(name)s.%(levelname)s %(message)s"
logging_FILE = "/var/log/pdudaemon.log"

##################
# Global logger
##################
logger = logging.getLogger('pdud')


def setup_logging(options, settings):
    logger = logging.getLogger("pdud")
    """
    Setup the log handler and the log level
    """
    if options.journal:
        from systemd.journal import JournalHandler
        handler = JournalHandler(SYSLOG_IDENTIFIER="pdudaemon")
        handler.setFormatter(logging.Formatter(logging_FORMAT_JOURNAL))
    elif options.logfile == "-" or not options.logfile:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(logging_FORMAT))
    else:
        handler = WatchedFileHandler(options.logfile)
        handler.setFormatter(logging.Formatter(logging_FORMAT))

    logger.addHandler(handler)
    settings_level = settings.get('daemon', {}).get('logging_level', None)
    if settings_level:
        options.loglevel = settings_level.upper()
    else:
        options.loglevel = options.loglevel.upper()
    if options.loglevel == "DEBUG":
        logger.setLevel(logging.DEBUG)
    elif options.loglevel == "INFO":
        logger.setLevel(logging.INFO)
    elif options.loglevel == "WARNING":
        logger.setLevel(logging.WARNING)
    else:
        logger.setLevel(logging.ERROR)


async def main_async():
    # Setup the parser
    parser = argparse.ArgumentParser()

    log = parser.add_argument_group("logging")
    log.add_argument("--journal", "-j", action="store_true", default=False,
                     help="Log to the journal")
    log.add_argument("--logfile", dest="logfile", action="store", type=str,
                     default="-", help="log file [%s]" % logging_FILE)
    log.add_argument("--loglevel", dest="loglevel", default="INFO",
                     choices=["DEBUG", "ERROR", "INFO", "WARN"],
                     type=str, help="logging level [INFO]")
    parser.add_argument("--conf", "-c", type=argparse.FileType("r"),
                        default=CONFIGURATION_FILE,
                        help="configuration file [%s]" % CONFIGURATION_FILE)
    parser.add_argument("--listener", type=str, help="PDUDaemon listener setting")
    conflict = parser.add_mutually_exclusive_group()
    conflict.add_argument("--alias", dest="alias", action="store", type=str)
    conflict.add_argument("--hostname", dest="drivehostname", action="store", type=str)
    drive = parser.add_argument_group("drive")
    drive.add_argument("--drive", action="store_true", default=False)
    drive.add_argument("--request", dest="driverequest", action="store", type=str)
    drive.add_argument("--retries", dest="driveretries", action="store", type=int, default=5)
    drive.add_argument("--port", dest="driveport", action="store", type=int)

    # Parse the command line
    options = parser.parse_args()

    # Read the configuration file
    try:
        settings = json.loads(options.conf.read())
    except Exception as exc:
        logging.error("Unable to read configuration file '%s': %s", options.conf.name, exc)
        return 1

    # Setup logging
    setup_logging(options, settings)

    if options.drive:
        # Driving a PDU directly, dont start any Listeners

        if options.alias:
            # Using alias support, get all pdu info from alias
            alias_settings = settings["aliases"].get(options.alias, False)
            if not alias_settings:
                logging.error("Alias requested but not found")
                sys.exit(1)
            options.drivehostname = settings["aliases"][options.alias]["hostname"]
            options.driveport = settings["aliases"][options.alias]["port"]

        # Check that the requested PDU has config
        config = settings["pdus"].get(options.drivehostname, False)
        if not config:
            logging.error("No config section for hostname: {}".format(options.drivehostname))
            sys.exit(1)

        runner = PDURunner(config, options.drivehostname, options.driveretries)
        if options.driverequest == "reboot":
            result = await runner.do_job_async(options.driveport, "off")
            result = await runner.do_job_async(options.driveport, "on")
        else:
            result = await runner.do_job_async(options.driveport, options.driverequest)
        return result

    logger.info('PDUDaemon starting up')

    # Context
    loop = asyncio.get_running_loop()
    runners = {}

    # Create the runners
    logger.info("Creating the runners")
    for hostname in settings["pdus"]:
        config = settings["pdus"][hostname]
        retries = config.get("retries", 5)
        runners[hostname] = PDURunner(config, hostname, retries)

    # Start the listener
    logger.info("Starting the listener")
    if options.listener:
        listener = options.listener
    else:
        listener = settings['daemon'].get('listener', 'tcp')
    if listener == 'tcp':
        listener = TCPListener(settings, runners)
    elif listener == 'http':
        listener = HTTPListener(settings, runners)
    else:
        logging.error("Unknown listener configured")

    # Setup signal handling
    def signal_handler(signum, frame):
        logger.info("Signal received, shutting down the loop")
        loop.stop()

    await listener.start()

    #signal.signal(signal.SIGINT, signal_handler)
    #signal.signal(signal.SIGTERM, signal_handler)

def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main_async())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    # execute only if run as a script
    result = main()
    sys.exit(result)
