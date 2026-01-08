package org.v.commons.utils;

import io.getunleash.DefaultUnleash;
import io.getunleash.Unleash;
import io.getunleash.util.UnleashConfig;

public class UnleashServerUtility {
    public static Unleash createUnleashClient(String appName,
                                              String instanceId,
                                              String unleashUrl,
                                              String unleashApiToken) {
        return new DefaultUnleash(UnleashConfig.builder()
                .appName(appName)
                .instanceId(instanceId)
                .unleashAPI(unleashUrl)
                .apiKey(unleashApiToken)
                .synchronousFetchOnInitialisation(true)
                .fetchTogglesInterval(5)
                .build());
    }
}
