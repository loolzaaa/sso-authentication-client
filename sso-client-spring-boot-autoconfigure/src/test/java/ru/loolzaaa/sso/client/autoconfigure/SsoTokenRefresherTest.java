package ru.loolzaaa.sso.client.autoconfigure;

import org.junit.jupiter.api.Test;
import ru.loolzaaa.sso.client.core.security.token.TokenDataReceiver;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class SsoTokenRefresherTest {

    @Test
    void shouldDelegateToReceiverWithConfiguredBeforeExpiry() {
        TokenDataReceiver receiver = mock(TokenDataReceiver.class);
        SsoClientProperties.Refresh refresh = new SsoClientProperties.Refresh();
        refresh.setEnabled(false);
        refresh.setBeforeExpiry(Duration.ofSeconds(42));

        SsoTokenRefresher refresher = new SsoTokenRefresher(receiver, refresh);
        refresher.refresh();
        refresher.destroy();

        verify(receiver).updateDataIfExpiringWithin(Duration.ofSeconds(42));
    }

    @Test
    void shouldSwallowRefreshErrors() {
        TokenDataReceiver receiver = mock(TokenDataReceiver.class);
        doThrow(new IllegalStateException("boom")).when(receiver).updateDataIfExpiringWithin(any());
        SsoClientProperties.Refresh refresh = new SsoClientProperties.Refresh();
        refresh.setEnabled(false);

        SsoTokenRefresher refresher = new SsoTokenRefresher(receiver, refresh);

        assertDoesNotThrow(refresher::refresh);
        refresher.destroy();
    }
}
