package com.gw2auth.oauth2.server.web;

import com.gw2auth.oauth2.server.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
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

    @ParameterizedTest
    @WithGw2AuthLogin
    public void authInfo(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(head("/api/authinfo").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isAccepted());
    }
}