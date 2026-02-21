const checkOverlap = (a, b) => new Date(a.startDate) <= new Date(b.endDate) && new Date(b.startDate) <= new Date(a.endDate);
const kernel = {startDate: "2026-02-24", endDate: "2026-02-26"};
const testphase = {startDate: "2026-02-24", endDate: "2026-03-10"};
console.log(checkOverlap(kernel, testphase));
const assigned = [];
[kernel, testphase].forEach(item => {
    const usedLanes = new Set();
    assigned.forEach(prev => { if (checkOverlap(prev, item)) usedLanes.add(prev.lane); });
    let lane = 0;
    while (usedLanes.has(lane)) lane++;
    assigned.push({ ...item, lane });
});
console.log(assigned);
