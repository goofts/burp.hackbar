package utils;

import java.io.File;
import java.util.List;
import java.util.Map;

import burp.IBurpExtenderCallbacks;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import pcap.reconst.ex.PcapException;
import pcap.reconst.http.datamodel.RecordedHttpFlow;
import pcap.reconst.tcp.*;
import burp.BurpExtender;

/**
 * HttpReconstructor
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */

public class HttpReconstructorUtils {
    private static Log log = LogFactory.getLog(HttpReconstructorUtils.class);

    public static void loadPcap(IBurpExtenderCallbacks callbacks, File pcapFile, StatusHandle statusHandle) throws PcapException {
        try {
            // Reassemble the TCP streams.
            Map<TcpConnection, TcpReassembler> map =
                    new PktsIoReconstructor(new PacketReassembler()).reconstruct(pcapFile.getAbsolutePath(), statusHandle);

            // Parse the HTTP flows from the streams.
            HttpFlowUtils httpParser = new HttpFlowUtils(callbacks, map);
            Map<TcpConnection, List<RecordedHttpFlow>> flows = httpParser.parse(statusHandle);

            // Count the total number of extracted flows.
            int flowcount = 0;
            for (TcpConnection key : flows.keySet()) {
                flowcount += flows.get(key).size();
            }
            callbacks.printOutput("Parsed " + flowcount + " total flows.");
        }
        catch (PcapException pce)
        {
            //These can propagate up the stack - all other exceptions are squashed below
            throw pce;
        }
        catch (Exception e) {
            if (log.isErrorEnabled()) {
                log.error("", e);
            }
        }
    }
}