import React from 'react';
import { Shield, AlertTriangle, Activity, Wifi, Lock, TrendingUp } from 'lucide-react';

const Dashboard = () => {
  const stats = [
    {
      title: 'Total Scans Today',
      value: '1,247',
      change: '+12%',
      changeType: 'positive',
      icon: Activity,
      color: 'from-blue-500 to-cyan-500'
    },
    {
      title: 'Threats Detected',
      value: '23',
      change: '-5%',
      changeType: 'negative',
      icon: AlertTriangle,
      color: 'from-red-500 to-pink-500'
    },
    {
      title: 'Clean Files',
      value: '1,224',
      change: '+8%',
      changeType: 'positive',
      icon: Shield,
      color: 'from-green-500 to-emerald-500'
    },
    {
      title: 'Open Ports Found',
      value: '127',
      change: '+2%',
      changeType: 'neutral',
      icon: Wifi,
      color: 'from-yellow-500 to-orange-500'
    },
  ];

  const recentThreats = [
    {
      id: 1,
      name: 'Trojan.GenKryptik.64834',
      severity: 'High',
      source: 'suspicious_file.exe',
      time: '2 minutes ago',
      status: 'quarantined'
    },
    {
      id: 2,
      name: 'Malicious URL Detected',
      severity: 'Medium',
      source: 'http://malicious-site.com',
      time: '15 minutes ago',
      status: 'blocked'
    },
    {
      id: 3,
      name: 'Port 445 Vulnerable',
      severity: 'Medium',
      source: '192.168.1.100',
      time: '1 hour ago',
      status: 'monitoring'
    },
    {
      id: 4,
      name: 'Suspicious USB Activity',
      severity: 'Low',
      source: 'USB Device F:/',
      time: '2 hours ago',
      status: 'scanned'
    },
  ];

  return (
    <div className="space-y-6">
      {/* Welcome Section */}
      <div className="bg-gradient-to-r from-gray-800 to-gray-700 rounded-xl p-6 border border-gray-600">
        <h2 className="text-2xl font-bold mb-2">Threat Intelligence Dashboard</h2>
        <p className="text-gray-300">Real-time monitoring and analysis of your security posture</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat, index) => {
          const IconComponent = stat.icon;
          return (
            <div
              key={index}
              className="bg-gray-800 rounded-xl p-6 border border-gray-700 hover:border-gray-600 transition-all duration-300 group"
            >
              <div className="flex items-center justify-between mb-4">
                <div className={`p-3 rounded-lg bg-gradient-to-r ${stat.color} bg-opacity-20`}>
                  <IconComponent className="h-6 w-6 text-white" />
                </div>
                <div className={`flex items-center text-sm ${
                  stat.changeType === 'positive' ? 'text-green-400' : 
                  stat.changeType === 'negative' ? 'text-red-400' : 
                  'text-yellow-400'
                }`}>
                  <TrendingUp className="h-4 w-4 mr-1" />
                  {stat.change}
                </div>
              </div>
              <div>
                <p className="text-2xl font-bold text-white group-hover:text-cyan-400 transition-colors">
                  {stat.value}
                </p>
                <p className="text-gray-400 text-sm mt-1">{stat.title}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Threats */}
        <div className="bg-gray-800 rounded-xl border border-gray-700">
          <div className="p-6 border-b border-gray-700">
            <h3 className="text-lg font-semibold flex items-center">
              <AlertTriangle className="h-5 w-5 text-red-400 mr-2" />
              Recent Threats
            </h3>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {recentThreats.map((threat) => (
                <div
                  key={threat.id}
                  className="flex items-center justify-between p-4 bg-gray-700/50 rounded-lg border border-gray-600 hover:border-gray-500 transition-all duration-200"
                >
                  <div className="flex-1">
                    <h4 className="font-medium text-white">{threat.name}</h4>
                    <p className="text-sm text-gray-400 mt-1">{threat.source}</p>
                  </div>
                  <div className="text-right">
                    <span className={`inline-block px-2 py-1 rounded text-xs font-medium ${
                      threat.severity === 'High' ? 'bg-red-500/20 text-red-400' :
                      threat.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      {threat.severity}
                    </span>
                    <p className="text-xs text-gray-500 mt-1">{threat.time}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* System Status */}
        <div className="bg-gray-800 rounded-xl border border-gray-700">
          <div className="p-6 border-b border-gray-700">
            <h3 className="text-lg font-semibold flex items-center">
              <Activity className="h-5 w-5 text-green-400 mr-2" />
              System Status
            </h3>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-gray-300">Real-time Protection</span>
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse"></div>
                  <span className="text-green-400 text-sm font-medium">Active</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-300">Firewall Status</span>
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse"></div>
                  <span className="text-green-400 text-sm font-medium">Enabled</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-300">USB Monitoring</span>
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse"></div>
                  <span className="text-green-400 text-sm font-medium">Active</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-300">Network Scanner</span>
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-yellow-400 rounded-full mr-2 animate-pulse"></div>
                  <span className="text-yellow-400 text-sm font-medium">Idle</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-300">Database Updates</span>
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse"></div>
                  <span className="text-green-400 text-sm font-medium">Updated</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;