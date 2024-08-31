import { CircularProgress, Box } from '@mui/material';

const LoadingComponent = () => {
  return (
    <Box
      sx={{
        backgroundImage: 'url(/all_background.png)',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat',
        height: '100vh',
        width: '100vw',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexDirection: 'column',
        color: '#ffffff',
        overflowX: 'hidden',
      }}
    >
        <CircularProgress
        size={80}
        thickness={5}
        sx={{
          color: 'white',
          marginBottom: '20px',
        }}
      />
    </Box>
  );
};

export default LoadingComponent;
