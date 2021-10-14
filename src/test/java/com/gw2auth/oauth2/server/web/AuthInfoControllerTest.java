package com.gw2auth.oauth2.server.web;

import com.gw2auth.oauth2.server.Gw2AuthLoginExtension;
import com.gw2auth.oauth2.server.Gw2AuthTestComponentScan;
import com.gw2auth.oauth2.server.TruncateTablesExtension;
import com.gw2auth.oauth2.server.WithGw2AuthLogin;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Gw2AuthTestComponentScan
class AuthInfoControllerTest {

    @Autowired
    @RegisterExtension
    TruncateTablesExtension truncateTablesExtension;

    @Autowired
    @RegisterExtension
    Gw2AuthLoginExtension gw2AuthLoginExtension;

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void authInfoUnauthorized() throws Exception {
        this.mockMvc.perform(head("/api/authinfo"))
                .andExpect(status().isUnauthorized());
    }

    @WithGw2AuthLogin
    public void authInfo(MockHttpSession session) throws Exception {
        this.mockMvc.perform(head("/api/authinfo").session(session))
                .andExpect(status().isAccepted());
    }
}