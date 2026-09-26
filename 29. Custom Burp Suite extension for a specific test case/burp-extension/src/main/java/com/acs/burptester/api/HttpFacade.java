package com.acs.burptester.api;

public interface HttpFacade {

    FacadeResponse send(FacadeRequest request);
}