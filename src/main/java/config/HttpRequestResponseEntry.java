package config;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import pcap.reconst.http.HttpFlowParser;
import pcap.reconst.tcp.TcpConnection;
import pcap.reconst.tcp.TcpReassembler;

import java.util.Map;

/**
 * HttpRequestResponseEntry
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class HttpRequestResponseEntry implements IHttpRequestResponse {
    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;
    private IHttpService httpService;

    public HttpRequestResponseEntry(byte[] request, byte[] response) {
        super();
        this.request = request;
        this.response = response;
    }

    public byte[] getRequest() {
        return request;
    }

    public void setRequest(byte[] message) {
        this.request = message;
    }

    public byte[] getResponse() {
        return response;
    }

    public void setResponse(byte[] message) {
        this.response = message;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getHighlight() {
        return highlight;
    }

    public void setHighlight(String color) {
        this.highlight = color;
    }

    public IHttpService getHttpService() {
        return httpService;
    }

    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }
}