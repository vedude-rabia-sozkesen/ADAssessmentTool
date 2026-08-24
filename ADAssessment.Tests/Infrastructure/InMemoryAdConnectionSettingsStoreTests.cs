using ADAssessment.Infrastructure.Configuration;
using ADAssessment.Infrastructure.Ldap;
using Xunit;

namespace ADAssessment.Tests.Infrastructure
{
    public class InMemoryAdConnectionSettingsStoreTests
    {
        [Fact]
        public void GetCurrent_NothingSet_ReturnsNull()
        {
            var store = new InMemoryAdConnectionSettingsStore();

            Assert.Null(store.GetCurrent());
        }

        [Fact]
        public void Set_ThenGetCurrent_ReturnsSameOptions()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var options = new LdapConnectionOptions { LdapPath = "LDAPS://10.0.0.1:636/DC=test,DC=local", Username = "svc-test" };

            store.Set(options);

            Assert.Same(options, store.GetCurrent());
        }

        [Fact]
        public void Clear_AfterSet_ReturnsNullAgain()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            store.Set(new LdapConnectionOptions { LdapPath = "LDAPS://10.0.0.1:636/DC=test,DC=local" });

            store.Clear();

            Assert.Null(store.GetCurrent());
        }

        [Fact]
        public void Set_Twice_LatestValueWins()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            store.Set(new LdapConnectionOptions { LdapPath = "LDAPS://10.0.0.1:636/DC=first,DC=local" });
            var second = new LdapConnectionOptions { LdapPath = "LDAPS://10.0.0.2:636/DC=second,DC=local" };

            store.Set(second);

            Assert.Same(second, store.GetCurrent());
        }
    }
}
