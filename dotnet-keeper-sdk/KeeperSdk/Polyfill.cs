using System;
using System.Collections.Generic;
using System.Text;

namespace KeeperSecurity.Sdk
{
    public static class DateTimeOffsetExtensions
    {
#if UNIX_EPOCH
        internal static long Epoch = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero).UtcTicks;
             
        public static long ToUnixTimeMilliseconds(this DateTimeOffset date)
        {
            return (date.UtcTicks - Epoch) / TimeSpan.TicksPerMillisecond;
        }

        public static DateTimeOffset FromUnixTimeMilliseconds(this long milliseconds)
        {
            return new DateTimeOffset(milliseconds * TimeSpan.TicksPerMillisecond + Epoch, TimeSpan.Zero);
        }
#else
        public static DateTimeOffset FromUnixTimeMilliseconds(this long milliseconds)
        {
            return DateTimeOffset.FromUnixTimeMilliseconds(milliseconds);
        }
#endif
    }
}
