import React from 'react';
import PropTypes from 'prop-types';
import clsx from 'clsx';

const Button = ({ href, children, className, ...props }) => {
  const baseClasses = 'py-3 px-6 rounded-lg text-lg font-semibold transition-colors duration-300';

  const classes = clsx(
    baseClasses,
    className,
    {
      'hover:bg-opacity-80': true, // Example of additional styling
    }
  );

  if (href) {
    return (
      <a href={href} className={classes} {...props}>
        {children}
      </a>
    );
  }

  return (
    <button className={classes} {...props}>
      {children}
    </button>
  );
};

Button.propTypes = {
  href: PropTypes.string,
  children: PropTypes.node.isRequired,
  className: PropTypes.string,
};

Button.defaultProps = {
  href: null,
  className: '',
};

export default Button;
