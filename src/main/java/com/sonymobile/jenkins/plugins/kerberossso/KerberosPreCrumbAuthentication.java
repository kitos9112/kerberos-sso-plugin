/*
 *  The MIT License
 *
 *  Copyright (c) 2014 Sony Mobile Communications Inc. All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

package com.sonymobile.jenkins.plugins.kerberossso;

import hudson.Extension;
import hudson.Functions;
import hudson.security.csrf.CrumbExclusion;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Establishes request authentication before Jenkins validates a POST's crumb.
 *
 * Core runs CrumbFilter before PluginServletFilter, so a per-request machine identity would otherwise
 * be anonymous at validation time. CrumbExclusion is the pre-validation callback: despite its name,
 * this extension never exempts an authenticated request from CSRF checks. It returns false after
 * authentication so core validates the crumb normally. It only returns true when negotiation has
 * already handled the response, without invoking the downstream chain.
 */
@Extension
public class KerberosPreCrumbAuthentication extends CrumbExclusion {

    @Override
    public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        PluginImpl plugin = PluginImpl.getInstance();
        if (!plugin.getEnabled() || plugin.getMachinePrincipalPatterns().isEmpty() || !Functions.isAnonymous()) {
            return false;
        }
        KerberosSSOFilter filter = plugin.getFilter();
        if (filter == null || !filter.isActive()) {
            return false;
        }

        AtomicBoolean continueValidation = new AtomicBoolean();
        filter.doFilter(request, response, (req, rsp) -> continueValidation.set(true));
        return !continueValidation.get();
    }
}
