import React, { useEffect, useState } from "react";
import axios from "axios";
import {
  Box,
  Container,
  Typography,
  Paper,
  List,
  ListItem,
  ListItemText,
  Button,
  Collapse,
  Grid,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import { Doughnut } from "react-chartjs-2";
import { Chart, ArcElement, Tooltip, Legend } from "chart.js";
import "chart.js/auto";
import "./Vulnerabilities.css";
import LoadingComponent from "./Loading";
import BASE_URL from "./baseURL";

Chart.register(ArcElement, Tooltip, Legend);

function Vulnerabilities() {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState({});
  const [chartData, setChartData] = useState({});
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) {
      navigate('/login')
    }
    axios
      .get(`${BASE_URL}/api/vulnerabilities`)
      .then((response) => {
        const data = generateChartData(response.data);
        setVulnerabilities(response.data);
        setChartData(data);
        setLoading(false);
      })
      .catch((error) => {
        console.error(
          "There was an error fetching the vulnerabilities!",
          error
        );
        setVulnerabilities([]);
        setLoading(false);
      });
  }, [vulnerabilities, chartData]);

  const handleExpandClick = (key) => {
    setExpanded((prevExpanded) => ({
      ...prevExpanded,
      [key]: !prevExpanded[key],
    }));
  };

  // Generate chart data based on the vulnerabilities data
  const generateChartData = (vulnerabilities) => {
    const labels = Object.keys(vulnerabilities);
    const data = Object.values(vulnerabilities).map((routes) => routes.length);

    return {
      labels,
      datasets: [
        {
          data,
          backgroundColor: [
            "#0088FE",
            "#00C49F",
            "#FFBB28",
            "#FF8042",
            "#c101fb",
            "#f45c42",
            "#42a7f4",
            "#f442e4",
            "#32CD32",
            "#FF4500" 
          ],
          hoverOffset: 4,
        },
      ],
    };
  };

  // Function to count the total number of vulnerable routes
  const getTotalVulnerabilitiesCount = () => {
    return Object.values(vulnerabilities).reduce(
      (total, routes) => total + routes.length,
      0
    );
  };

  if (loading) {
    return <LoadingComponent />;
  }

  const totalVulnerabilities = getTotalVulnerabilitiesCount();

  return (
    <Box
      sx={{
        backgroundImage: "url(/all_background.png)",
        backgroundSize: "cover",
        backgroundPosition: "center",
        backgroundAttachment: "fixed",
        minHeight: "100vh",
        minWidth: "100vw",
        color: "#ffffff",
        overflowX: "hidden",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        flexDirection: "column",
      }}
    >
      <Container
        maxWidth="lg"
        sx={{
          position: "relative",
          zIndex: 2,
          paddingTop: "0",
        }}
      >
        <Typography
          variant="h4"
          align="center"
          gutterBottom
          sx={{
            marginBottom: "1rem",
            marginTop: "0",
            color: "#fff",
          }}
        >
          Vulnerabilities
        </Typography>
        <Typography
          variant="h6"
          align="center"
          gutterBottom
          sx={{
            marginBottom: "2rem",
            color: "#ffffff",
            fontWeight: "bold",
          }}
        >
          Total Vulnerabilities Found: {totalVulnerabilities}
        </Typography>

        <Grid container spacing={4}>
          <Grid item xs={12} md={6}>
            <Doughnut
              data={chartData}
              options={{
                responsive: true,
                cutout: "60%", // This makes the chart hollow (doughnut)
                animation: {
                  animateRotate: true,
                  duration: 2000,
                },
                plugins: {
                  legend: {
                    position: "bottom",
                  },
                  tooltip: {
                    callbacks: {
                      label: (tooltipItem) => {
                        const label = chartData.labels[tooltipItem.dataIndex];
                        const value =
                          chartData.datasets[0].data[tooltipItem.dataIndex];
                        return `${label}: ${value}`;
                      },
                    },
                  },
                },
              }}
            />
          </Grid>

          <Grid item xs={12} md={6}>
            <Box className="horizontal-scroll">
              {Object.entries(vulnerabilities).map(([key, value], index) => (
                <div className="card-item" key={index}>
                  <Paper
                    elevation={4}
                    sx={{
                      width: "300px",
                      height: "180px",
                      display: "flex",
                      flexDirection: "column",
                      justifyContent: "space-between",
                      backgroundColor: "rgba(55, 55, 100, 0.8)",
                      backdropFilter: "blur(10px)",
                      borderRadius: "12px",
                      boxShadow: "0px 4px 15px rgba(0, 0, 0, 0.3)",
                      padding: "1.5rem",
                      textAlign: "center",
                      overflow: "hidden",
                      position: "relative",
                    }}
                  >
                    <Typography
                      variant="h6"
                      sx={{
                        fontWeight: "bold",
                        color: "#ffffff",
                        textShadow: "1px 1px 3px rgba(0, 0, 0, 0.3)",
                        marginBottom: "1rem",
                        opacity: expanded[key] ? 0 : 1,
                        transition: "opacity 0.3s ease-in-out",
                      }}
                    >
                      {key}
                    </Typography>
                    <Collapse in={expanded[key]} timeout="auto" unmountOnExit>
                      <Box
                        sx={{
                          overflowY: "auto", // Ensures that content can scroll
                          maxHeight: "calc(100% - 64px)", // Adjust this value based on the height of your button and any other padding or margins you might have
                          paddingTop: "1rem",
                          position: "absolute",
                          top: 0,
                          left: 0,
                          right: 0,
                          bottom: "64px", // Reserve space for the button
                          display: "flex",
                          flexDirection: "column",
                          justifyContent: "start", // Align content to the top
                          transition: "transform 0.3s ease-in-out",
                          "&::-webkit-scrollbar": {
                            width: "8px",
                            backgroundColor: "rgba(0, 0, 0, 0.2)",
                          },
                          "&::-webkit-scrollbar-thumb": {
                            backgroundColor: "#c101fb",
                            borderRadius: "8px",
                          },
                        }}
                      >
                        <List>
                          {Array.isArray(value) ? (
                            value.map((vuln, idx) => (
                              <ListItem key={idx} sx={{ paddingLeft: 0 }}>
                                <ListItemText
                                  primary={
                                    <Link
                                      to={`/api-details/${vuln.replace(
                                        "/",
                                        ""
                                      )}`}
                                      style={{
                                        color: "#ffffff",
                                        textDecoration: "none",
                                        wordBreak: "break-all",
                                        marginLeft: "80px"
                                      }}
                                    >
                                      {vuln}
                                    </Link>
                                  }
                                />
                              </ListItem>
                            ))
                          ) : (
                            <Typography
                              variant="body1"
                              sx={{ color: "#ffffff" }}
                            >
                              No vulnerabilities found for {key}.
                            </Typography>
                          )}
                        </List>
                      </Box>
                    </Collapse>
                    {!expanded[key] && (
                      <Button
                        variant="contained"
                        color="primary"
                        onClick={() => handleExpandClick(key)}
                        sx={{
                          backgroundColor: "#c101fb",
                          marginTop: "1rem",
                          "&:hover": {
                            backgroundColor: "#a000d0",
                          },
                          position: "absolute",
                          bottom: "1rem",
                          left: "50%",
                          transform: "translateX(-50%)",
                        }}
                      >
                        {expanded[key] ? "Hide Routes" : "View Routes"}
                      </Button>
                    )}
                    {expanded[key] && (
                      <Button
                        variant="contained"
                        color="primary"
                        onClick={() => handleExpandClick(key)}
                        sx={{
                          backgroundColor: "#c101fb",
                          marginTop: "1rem",
                          "&:hover": {
                            backgroundColor: "#a000d0",
                          },
                          position: "absolute",
                          bottom: "1rem",
                          left: "50%",
                          transform: "translateX(-50%)",
                        }}
                      >
                        Hide Routes
                      </Button>
                    )}
                  </Paper>
                </div>
              ))}
            </Box>
          </Grid>
        </Grid>
      </Container>
    </Box>
  );
}

export default Vulnerabilities;
