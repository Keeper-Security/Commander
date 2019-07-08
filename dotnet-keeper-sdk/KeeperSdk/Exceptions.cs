//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2019 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
namespace KeeperSecurity.Sdk
{
    public class KeeperInvalidParameter : Exception
    {
        public KeeperInvalidParameter(string method, string parameter, string value, string message) : base(message)
        {
            Method = method;
            Parameter = parameter;
            Value = value;
        }

        public string Method { get; }
        public string Parameter { get; }
        public string Value { get; }
    }

    public class KeeperApiException : Exception
    {
        public KeeperApiException(string code, string message) : base(message)
        {
            Code = code;
        }

        public string Code { get; }
    }

    public class KeeperRegionRedirect : Exception
    {
        public KeeperRegionRedirect(string regionHost)
        {
            RegionHost = regionHost;
        }

        public string RegionHost { get; set; }
    }

    public class KeeperInvalidDeviceToken : Exception
    {
    }

    public class KeeperTooManyAttempts : Exception
    {
    }

    public class KeeperRequiresUI : Exception
    {
    }
}
