import React from 'react';

interface StepCardProps {
  title: string;
  status: 'pending' | 'success' | 'error' | 'active';
  children: React.ReactNode;
}

const StepCard: React.FC<StepCardProps> = ({ title, status, children }) => {
  const getBorderColor = () => {
    switch (status) {
      case 'success': return 'border-green-500';
      case 'error': return 'border-red-500';
      case 'active': return 'border-blue-500';
      default: return 'border-gray-200';
    }
  };

  const getIcon = () => {
    switch (status) {
      case 'success': return (
        <svg className="w-6 h-6 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
      );
      case 'error': return (
        <svg className="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
      );
      case 'active': return (
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
      );
      default: return (
        <div className="w-6 h-6 rounded-full border-2 border-gray-300"></div>
      );
    }
  };

  return (
    <div className={`bg-white rounded-lg shadow-sm border-l-4 p-6 mb-4 ${getBorderColor()}`}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-800">{title}</h3>
        {getIcon()}
      </div>
      <div className="text-gray-600">
        {children}
      </div>
    </div>
  );
};

export default StepCard;
