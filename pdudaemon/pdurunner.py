#!/usr/bin/python3

#  Copyright 2013 Linaro Limited
#  Author Matt Hart <matthew.hart@linaro.org>
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

import asyncio
import logging
import time
import traceback
import pexpect
from pdudaemon.drivers.driver import PDUDriver
import pdudaemon.drivers.strategies  # pylint: disable=W0611


class PDURunner:

    def __init__(self, config, hostname, retries):
        self.config = config
        self.hostname = hostname
        self.retries = retries
        self.logger = logging.getLogger("pdud.pdu.%s" % hostname)
        self.driver = self.driver_from_hostname(hostname)
        self.lock = asyncio.Lock()

    def driver_from_hostname(self, hostname):
        drivername = self.config['driver']
        driver = PDUDriver.select(drivername)(hostname, self.config)
        return driver

    def do_job(self, port, request):
        retries = self.retries
        while retries > 0:
            try:
                return self.driver.handle(request, port)
            except (OSError, pexpect.exceptions.EOF, Exception):  # pylint: disable=broad-except
                self.logger.warn(traceback.format_exc())
                self.logger.warn("Failed to execute job: %s %s (attempts left %i)", port, request, retries - 1)
                if self.driver:
                    self.driver._bombout()  # pylint: disable=W0212,E1101
                time.sleep(5)
                retries -= 1
                continue
        return False

    async def do_job_async(self, port, request):
        loop = asyncio.get_running_loop()
        async with self.lock:
            self.logger.info("Processing task (%s %s)", request, port)
            result = await loop.run_in_executor(None, self.do_job, port, request)
            return result
