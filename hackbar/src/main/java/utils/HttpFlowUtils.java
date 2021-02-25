package utils;

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import burp.IRequestInfo;
import config.HttpRequestResponseEntry;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpException;
import pcap.reconst.http.HttpFlowParser;
import pcap.reconst.http.datamodel.RecordedHttpFlow;
import pcap.reconst.http.datamodel.RecordedHttpRequestMessage;
import pcap.reconst.http.datamodel.RecordedHttpResponse;
import pcap.reconst.tcp.TcpConnection;
import pcap.reconst.tcp.TcpReassembler;

import java.io.IOException;
import java.util.Map;

/**
 * HttpFlowUtils
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class HttpFlowUtils extends HttpFlowParser {
    public IBurpExtenderCallbacks mCallbacks;
    private FlowBuf flow;
    private static Log log = LogFactory.getLog(HttpFlowParser.class);

    public HttpFlowUtils(IBurpExtenderCallbacks callbacks, Map<TcpConnection, TcpReassembler> map) {
        super(map);
        this.mCallbacks = callbacks;
    }

    @Override
    protected RecordedHttpFlow toHttp(final FlowBuf flow, final TcpReassembler assembler) throws IOException, HttpException {
        if (log.isDebugEnabled()) {
            log.debug("Processing flow " + flow);
        }

        byte[] rawdata = null;
        if (flow.hasRequestData()) {
            PcapRequestResponse rr = new PcapRequestResponse(mCallbacks, flow, assembler);
            mCallbacks.addToSiteMap(rr);
            IHttpService rrServ = rr.getHttpService();
            mCallbacks.doPassiveScan(rrServ.getHost(), rrServ.getPort(), false, rr.getRequest(), rr.getResponse());

            RecordedHttpRequestMessage request;
            RecordedHttpResponse response = null;

            rawdata = assembler.getOrderedPacketDataBytes(flow.reqStart, flow.reqEnd);

            if (flow.hadResponseData()) {
                byte[] respBytes = assembler.getOrderedPacketDataBytes(flow.respStart, flow.respEnd);
                byte[] reqRespbytes = new byte[rawdata.length + respBytes.length];
                System.arraycopy(rawdata, 0, reqRespbytes, 0, rawdata.length);
                System.arraycopy(respBytes, 0, reqRespbytes, rawdata.length, respBytes.length);
                rawdata = reqRespbytes;
                request = getRequest(flow, assembler);
                response = getResponse(flow, assembler);
            } else {
                request = getRequest(flow, assembler);
            }

            mCallbacks.printOutput("Parsed " + request.getUrl());
            return new RecordedHttpFlow(rawdata, request, response);
        }
        return null;
    }

    private static final class PcapRequestResponse extends HttpRequestResponseEntry {
        private final FlowBuf flow;
        private final TcpReassembler assembler;
        private IHttpService httpService;
        public IBurpExtenderCallbacks mCallbacks;

        private PcapRequestResponse(IBurpExtenderCallbacks callbacks, FlowBuf flow, TcpReassembler assembler)
        {
            super(HttpUtils.stripChunkedEncoding(HttpUtils.stripContinueFromRequests(assembler.getOrderedPacketDataBytes(flow.reqStart, flow.reqEnd))),
                    flow.respStart == -1 ? new byte[0] : HttpUtils.decompressIfRequired(HttpUtils.stripChunkedEncoding(assembler.getOrderedPacketDataBytes(flow.respStart, flow.respEnd))));

            this.flow = flow;
            this.assembler = assembler;
            this.mCallbacks = callbacks;
        }

        @Override
        public synchronized IHttpService getHttpService() {
            if (httpService == null)
            {
                IRequestInfo req = mCallbacks.getHelpers().analyzeRequest(getRequest());

                String host = null;
                for (String header : req.getHeaders())
                {
                    if(header.startsWith("Host: "))
                    {
                        host = header.substring("Host: ".length());
                        if (host.contains(":"))
                        {
                            String[] parts = host.split(":", 2);
                            if (parts.length == 2) {
                                httpService = mCallbacks.getHelpers().buildHttpService(
                                        parts[0],
                                        Integer.valueOf(parts[1]),
                                        false);
                                return httpService;
                            }
                        } else {
                            httpService = mCallbacks.getHelpers().buildHttpService(host, assembler.getTcpConnection(flow.reqStart, flow.reqEnd).getDstPort(), false);
                            return httpService;
                        }
                    }
                }

                httpService = mCallbacks.getHelpers().buildHttpService(
                        assembler.getTcpConnection(flow.reqStart, flow.reqEnd).getDstIp().getHostName(),
                        assembler.getTcpConnection(flow.reqStart, flow.reqEnd).getDstPort(),
                        false);
            }

            return httpService;
        }
    }
}